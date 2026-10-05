package com.example.identity_service.service.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.JwtProperties;
import com.example.identity_service.model.User;
import com.example.identity_service.service.authentication.AuthTokens;
import com.example.identity_service.service.authentication.AuthenticationService;
import com.example.identity_service.service.oauth2.ExternalLoginResult.Status;

// The real state service (so the cookie really carries state, nonce and verifier from the start to the
// return); everything that talks to Google or to the database is a mock.
class GoogleLoginFlowTest {

    private final GoogleOAuthClient googleClient = mock(GoogleOAuthClient.class);
    private final GoogleIdTokenVerifier idTokenVerifier = mock(GoogleIdTokenVerifier.class);
    private final ExternalLoginService externalLoginService = mock(ExternalLoginService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final OAuthLoginStateService stateService = new OAuthLoginStateService(
            new JwtProperties("flow-test-secret-".repeat(4), Duration.ofMinutes(15)), Clock.systemUTC());

    private final PendingLinkService pendingLinkService = new PendingLinkService(
            new JwtProperties("flow-test-secret-".repeat(4), Duration.ofMinutes(15)), Clock.systemUTC());

    private final GoogleLoginFlow flow = new GoogleLoginFlow(
            googleClient, stateService, idTokenVerifier, externalLoginService, authenticationService, pendingLinkService);

    private final ExternalIdentity identity = new ExternalIdentity(AuthProvider.GOOGLE, "sub-1", "user@gmail.com");
    private final AuthTokens tokens = new AuthTokens("access", "refresh", "Bearer", 900);

    // ---- start -----------------------------------------------------------------------------------

    @Test
    void startBuildsTheUrlFromTheSameValuesThatItPutInTheCookie() {
        when(googleClient.authorizationUrl(anyString(), anyString(), anyString())).thenReturn("https://google/auth");

        GoogleLoginFlow.Start start = flow.start();

        assertThat(start.authorizationUrl()).isEqualTo("https://google/auth");
        ArgumentCaptor<String> state = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> nonce = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> challenge = ArgumentCaptor.forClass(String.class);
        verify(googleClient).authorizationUrl(state.capture(), nonce.capture(), challenge.capture());
        // reading the cookie back with that state must give that nonce and a verifier of that challenge
        OAuthLoginStateService.ResumedLogin resumed =
                stateService.resume(AuthProvider.GOOGLE, start.stateCookieValue(), state.getValue());
        assertThat(resumed.nonce()).isEqualTo(nonce.getValue());
        assertThat(OAuthLoginStateService.codeChallengeFor(resumed.codeVerifier())).isEqualTo(challenge.getValue());
    }

    // ---- complete --------------------------------------------------------------------------------

    @Test
    void theReturnTradesTheCodeWithTheVerifierAndChecksTheTokenWithTheNonceOfThisLogin() {
        Login login = startLogin();
        when(googleClient.exchangeCode(anyString(), anyString())).thenReturn("the.id.token");
        when(idTokenVerifier.verify(anyString(), anyString())).thenReturn(identity);
        User user = User.builder().id(UUID.randomUUID()).email("user@gmail.com").build();
        when(externalLoginService.signIn(identity)).thenReturn(new ExternalLoginResult(Status.ACCOUNT_CREATED, user));
        when(authenticationService.loginAs(user)).thenReturn(tokens);

        GoogleLoginFlow.Completed completed = flow.complete("the-code", login.state(), login.cookie());

        assertThat(completed.status()).isEqualTo(Status.ACCOUNT_CREATED);
        assertThat(completed.identity()).isEqualTo(identity);
        assertThat(completed.tokens()).isEqualTo(tokens);
        assertThat(completed.pendingLinkCookieValue()).isNull();
        ArgumentCaptor<String> verifier = ArgumentCaptor.forClass(String.class);
        verify(googleClient).exchangeCode(org.mockito.ArgumentMatchers.eq("the-code"), verifier.capture());
        assertThat(OAuthLoginStateService.codeChallengeFor(verifier.getValue())).isEqualTo(login.challenge());
        verify(idTokenVerifier).verify("the.id.token", login.nonce());
    }

    @Test
    void aLinkedUserIsSignedInWithTokens() {
        Login login = startLogin();
        when(googleClient.exchangeCode(anyString(), anyString())).thenReturn("the.id.token");
        when(idTokenVerifier.verify(anyString(), anyString())).thenReturn(identity);
        User user = User.builder().id(UUID.randomUUID()).email("user@gmail.com").build();
        when(externalLoginService.signIn(identity)).thenReturn(new ExternalLoginResult(Status.SIGNED_IN, user));
        when(authenticationService.loginAs(user)).thenReturn(tokens);

        GoogleLoginFlow.Completed completed = flow.complete("the-code", login.state(), login.cookie());

        assertThat(completed.status()).isEqualTo(Status.SIGNED_IN);
        assertThat(completed.tokens()).isEqualTo(tokens);
    }

    @Test
    void whenTheEmailBelongsToAnotherUserNoTokensAreIssued() {
        Login login = startLogin();
        when(googleClient.exchangeCode(anyString(), anyString())).thenReturn("the.id.token");
        when(idTokenVerifier.verify(anyString(), anyString())).thenReturn(identity);
        when(externalLoginService.signIn(identity)).thenReturn(ExternalLoginResult.linkRequired());

        GoogleLoginFlow.Completed completed = flow.complete("the-code", login.state(), login.cookie());

        assertThat(completed.status()).isEqualTo(Status.LINK_REQUIRED);
        assertThat(completed.identity()).isEqualTo(identity);
        assertThat(completed.tokens()).isNull();
        verify(authenticationService, never()).loginAs(any());
        // what Google proved is kept for the confirmation step, and is exactly this identity
        assertThat(pendingLinkService.resume(completed.pendingLinkCookieValue())).isEqualTo(identity);
    }

    @Test
    void aReturnThatDoesNotMatchTheCookieStopsBeforeGoogleIsCalled() {
        Login login = startLogin();

        assertThatThrownBy(() -> flow.complete("the-code", "state-of-another-login", login.cookie()))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_OAUTH_STATE));

        verifyNoInteractions(idTokenVerifier, externalLoginService, authenticationService);
        verify(googleClient, never()).exchangeCode(anyString(), anyString());
    }

    @Test
    void aMissingCodeStopsBeforeGoogleIsCalled() {
        Login login = startLogin();

        assertThatThrownBy(() -> flow.complete(null, login.state(), login.cookie()))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_OAUTH_STATE));
        assertThatThrownBy(() -> flow.complete(" ", login.state(), login.cookie())).isInstanceOf(GeneralException.class);

        verify(googleClient, never()).exchangeCode(anyString(), anyString());
    }

    @Test
    void aTokenThatFailsVerificationCreatesNoUserAndIssuesNothing() {
        Login login = startLogin();
        when(googleClient.exchangeCode(anyString(), anyString())).thenReturn("forged.id.token");
        when(idTokenVerifier.verify(anyString(), anyString())).thenThrow(new GeneralException(ErrorCode.INVALID_ID_TOKEN));

        assertThatThrownBy(() -> flow.complete("the-code", login.state(), login.cookie()))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_ID_TOKEN));

        verifyNoInteractions(externalLoginService, authenticationService);
    }

    @Test
    void aFailureOfGoogleIsPassedOnAndCreatesNothing() {
        Login login = startLogin();
        when(googleClient.exchangeCode(anyString(), anyString())).thenThrow(new GeneralException(ErrorCode.INTERNAL_ERROR));

        assertThatThrownBy(() -> flow.complete("the-code", login.state(), login.cookie()))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR));

        verifyNoInteractions(idTokenVerifier, externalLoginService, authenticationService);
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private record Login(String state, String nonce, String challenge, String cookie) {
    }

    // Runs start() and captures what it sent to Google, as the browser would carry it back.
    private Login startLogin() {
        when(googleClient.authorizationUrl(anyString(), anyString(), anyString())).thenReturn("https://google/auth");
        GoogleLoginFlow.Start start = flow.start();
        ArgumentCaptor<String> state = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> nonce = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> challenge = ArgumentCaptor.forClass(String.class);
        verify(googleClient).authorizationUrl(state.capture(), nonce.capture(), challenge.capture());
        return new Login(state.getValue(), nonce.getValue(), challenge.getValue(), start.stateCookieValue());
    }
}
