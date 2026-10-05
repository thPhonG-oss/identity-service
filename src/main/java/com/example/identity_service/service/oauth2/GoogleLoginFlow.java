package com.example.identity_service.service.oauth2;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.service.authentication.AuthTokens;
import com.example.identity_service.service.authentication.AuthenticationService;
import com.example.identity_service.service.oauth2.OAuthLoginStateService.PendingLogin;
import com.example.identity_service.service.oauth2.OAuthLoginStateService.ResumedLogin;
import org.springframework.stereotype.Service;

/**
 * The login with Google from start to finish, in the two halves the browser makes:
 * {@link #start()} sends the user to Google, {@link #complete} handles their return.
 *
 * Every piece is somewhere else; this class only puts them in order.
 */
@Service
public class GoogleLoginFlow {

    private final GoogleOAuthClient googleClient;
    private final OAuthLoginStateService stateService;
    private final GoogleIdTokenVerifier idTokenVerifier;
    private final ExternalLoginService externalLoginService;
    private final AuthenticationService authenticationService;
    private final PendingLinkService pendingLinkService;

    public GoogleLoginFlow(GoogleOAuthClient googleClient, OAuthLoginStateService stateService,
            GoogleIdTokenVerifier idTokenVerifier, ExternalLoginService externalLoginService,
            AuthenticationService authenticationService, PendingLinkService pendingLinkService) {
        this.googleClient = googleClient;
        this.stateService = stateService;
        this.idTokenVerifier = idTokenVerifier;
        this.externalLoginService = externalLoginService;
        this.authenticationService = authenticationService;
        this.pendingLinkService = pendingLinkService;
    }

    /**
     * @param authorizationUrl where to send the browser
     * @param stateCookieValue what to put in the cookie that goes with that redirect
     */
    public record Start(String authorizationUrl, String stateCookieValue) {
    }

    /**
     * @param status   how the login turned out
     * @param identity who Google says the user is, always set
     * @param tokens   the tokens to give the user; {@code null} when the status is LINK_REQUIRED
     * @param pendingLinkCookieValue what to put in the cookie that lets the user confirm the link; only set
     *                 when the status is LINK_REQUIRED
     */
    public record Completed(ExternalLoginResult.Status status, ExternalIdentity identity, AuthTokens tokens,
            String pendingLinkCookieValue) {
    }

    public Start start() {
        PendingLogin pending = stateService.start(AuthProvider.GOOGLE);
        String url = googleClient.authorizationUrl(pending.state(), pending.nonce(), pending.codeChallenge());
        return new Start(url, pending.cookieValue());
    }

    /**
     * @param code            the authorization code Google put on the return address
     * @param state           the state Google put on the return address
     * @param stateCookieValue the cookie the browser sent back
     * @throws GeneralException when any step fails; see the exceptions of each step
     */
    public Completed complete(String code, String state, String stateCookieValue) {
        // 1. Is this return the answer to a login that started in this browser? Gives back what only this
        //    login knows: the nonce and the PKCE verifier.
        ResumedLogin resumed = stateService.resume(AuthProvider.GOOGLE, stateCookieValue, state);
        if (code == null || code.isBlank()) {
            throw new GeneralException(ErrorCode.INVALID_OAUTH_STATE);
        }

        // 2. Trade the code for tokens (needs the verifier), then check the ID token (needs the nonce).
        String idToken = googleClient.exchangeCode(code, resumed.codeVerifier());
        ExternalIdentity identity = idTokenVerifier.verify(idToken, resumed.nonce());

        // 3. Which user is this?
        ExternalLoginResult result = externalLoginService.signIn(identity);
        if (result.status() == ExternalLoginResult.Status.LINK_REQUIRED) {
            // Nothing is linked and nobody is signed in: the owner of the account must confirm first. What
            // Google proved is kept for that step, so they do not have to go through Google again.
            return new Completed(result.status(), identity, null, pendingLinkService.start(identity));
        }

        // 4. Give them the same tokens a login with a password gives.
        return new Completed(result.status(), identity, authenticationService.loginAs(result.user()), null);
    }
}
