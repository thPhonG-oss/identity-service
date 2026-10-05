package com.example.identity_service.controller;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.example.identity_service.config.ErrorResponseWriter;
import com.example.identity_service.config.JwtAccessDeniedHandler;
import com.example.identity_service.config.JwtAuthenticationEntryPoint;
import com.example.identity_service.config.OAuthStateCookieFactory;
import com.example.identity_service.config.PendingLinkCookieFactory;
import com.example.identity_service.config.RefreshTokenCookieFactory;
import com.example.identity_service.config.SecurityConfig;
import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.CorsProperties;
import com.example.identity_service.model.OAuth2LoginProperties;
import com.example.identity_service.model.RefreshCookieProperties;
import com.example.identity_service.model.RefreshTokenProperties;
import com.example.identity_service.service.authentication.AuthTokens;
import com.example.identity_service.service.authentication.JwtService;
import com.example.identity_service.service.oauth2.ExternalIdentity;
import com.example.identity_service.service.oauth2.ExternalLoginResult.Status;
import com.example.identity_service.service.oauth2.GoogleLoginFlow;

// The real security chain in front of the controller, to see that both endpoints are open to a user who is
// not logged in (the browser has no token yet), and the real cookie factories. The flow itself is mocked.
@WebMvcTest(GoogleAuthController.class)
@Import({ SecurityConfig.class, JwtAuthenticationEntryPoint.class, JwtAccessDeniedHandler.class,
        ErrorResponseWriter.class, RefreshTokenCookieFactory.class, OAuthStateCookieFactory.class, PendingLinkCookieFactory.class })
class GoogleAuthControllerTest {

    private static final String SPA = "http://localhost:5173";

    @TestConfiguration
    static class Settings {
        @Bean
        RefreshTokenProperties refreshTokenProperties() {
            return new RefreshTokenProperties(Duration.ofDays(7));
        }

        @Bean
        RefreshCookieProperties refreshCookieProperties() {
            return new RefreshCookieProperties(true, RefreshCookieProperties.SameSite.STRICT);
        }

        @Bean
        CorsProperties corsProperties() {
            return new CorsProperties(List.of(SPA));
        }

        @Bean
        OAuth2LoginProperties oAuth2LoginProperties() {
            return new OAuth2LoginProperties(SPA);
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private GoogleLoginFlow googleLoginFlow;

    private final ExternalIdentity identity = new ExternalIdentity(AuthProvider.GOOGLE, "sub-1", "user@gmail.com");

    // ---- start -----------------------------------------------------------------------------------

    @Test
    void authorizeSendsTheBrowserToGoogleAndRemembersTheLoginInACookie() throws Exception {
        when(googleLoginFlow.start()).thenReturn(new GoogleLoginFlow.Start("https://accounts.google.com/o/oauth2/v2/auth?x=1", "encrypted"));

        mockMvc.perform(get("/api/v1/auth/oauth2/google/authorize"))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, "https://accounts.google.com/o/oauth2/v2/auth?x=1"))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("oauth_state=encrypted")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("HttpOnly")))
                // Lax, so the browser sends it back when Google redirects to the callback
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("SameSite=Lax")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Path=/api/v1/auth/oauth2")));
    }

    // ---- the return: it worked -------------------------------------------------------------------

    @Test
    void aNewAccountIsSentToTheSpaWithTheRefreshCookieAndTheStateCookieIsDeleted() throws Exception {
        when(googleLoginFlow.complete("the-code", "the-state", "cookie"))
                .thenReturn(new GoogleLoginFlow.Completed(Status.ACCOUNT_CREATED, identity, new AuthTokens("a", "refresh-1", "Bearer", 900), null));

        mockMvc.perform(callback("code=the-code&state=the-state").cookie(stateCookie("cookie")))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, SPA + "/"))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("refresh_token=refresh-1"))))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("HttpOnly"))))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("oauth_state=;"))));
    }

    @Test
    void aReturningUserIsSentToTheSpaToo() throws Exception {
        when(googleLoginFlow.complete("the-code", "the-state", "cookie"))
                .thenReturn(new GoogleLoginFlow.Completed(Status.SIGNED_IN, identity, new AuthTokens("a", "refresh-2", "Bearer", 900), null));

        mockMvc.perform(callback("code=the-code&state=the-state").cookie(stateCookie("cookie")))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, SPA + "/"))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("refresh_token=refresh-2"))));
    }

    // ---- the return: it did not work -------------------------------------------------------------

    @Test
    void anEmailThatBelongsToAnotherUserSendsTheBrowserToTheConfirmationPageWithNoSession() throws Exception {
        when(googleLoginFlow.complete("the-code", "the-state", "cookie"))
                .thenReturn(new GoogleLoginFlow.Completed(Status.LINK_REQUIRED, identity, null, "pending-link"));

        mockMvc.perform(callback("code=the-code&state=the-state").cookie(stateCookie("cookie")))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, SPA + "/link-account"))
                // no session: only what Google proved, kept for the confirmation
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, everyItem(not(containsString("refresh_token")))))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("oauth_link=pending-link"))))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("HttpOnly"))))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("SameSite=Strict"))))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("Path=/api/v1/auth/oauth2/link"))))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("oauth_state=;"))));
    }

    // A confirmation left from an earlier attempt must not outlive a sign-in that went another way.
    @Test
    void aLeftOverConfirmationIsDeletedWhenTheLoginGoesAnotherWay() throws Exception {
        when(googleLoginFlow.complete("the-code", "the-state", "cookie"))
                .thenReturn(new GoogleLoginFlow.Completed(Status.SIGNED_IN, identity, new AuthTokens("a", "refresh-3", "Bearer", 900), null));

        mockMvc.perform(callback("code=the-code&state=the-state").cookie(stateCookie("cookie")))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("oauth_link=;"))));

        mockMvc.perform(callback("error=access_denied"))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("oauth_link=;"))));
    }

    @Test
    void theUserSayingNoAtGoogleIsAnErrorPageNotACrash() throws Exception {
        mockMvc.perform(callback("error=access_denied&state=the-state").cookie(stateCookie("cookie")))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, SPA + "/login?error=access_denied"))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("oauth_state=;"))));

        verify(googleLoginFlow, never()).complete(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void anotherErrorFromGoogleIsALoginFailure() throws Exception {
        mockMvc.perform(callback("error=server_error"))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, SPA + "/login?error=login_failed"));
    }

    @Test
    void aLoginThatFailsACheckIsALoginFailureWithoutTheReason() throws Exception {
        for (ErrorCode failed : new ErrorCode[] { ErrorCode.INVALID_OAUTH_STATE, ErrorCode.INVALID_ID_TOKEN, ErrorCode.INVALID_CREDENTIALS }) {
            // doThrow, not when(...): once the mock is set to throw, calling it again to re-stub would throw.
            doThrow(new GeneralException(failed)).when(googleLoginFlow).complete("the-code", "the-state", "cookie");

            mockMvc.perform(callback("code=the-code&state=the-state").cookie(stateCookie("cookie")))
                    .andExpect(status().isFound())
                    .andExpect(header().string(HttpHeaders.LOCATION, SPA + "/login?error=login_failed"))
                    .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("oauth_state=;"))));
        }
    }

    @Test
    void aProblemOnOurSideIsAServerError() throws Exception {
        when(googleLoginFlow.complete("the-code", "the-state", "cookie")).thenThrow(new GeneralException(ErrorCode.INTERNAL_ERROR));

        mockMvc.perform(callback("code=the-code&state=the-state").cookie(stateCookie("cookie")))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, SPA + "/login?error=server_error"));
    }

    // The browser must always land back on the SPA, not on a page of JSON.
    @Test
    void anUnexpectedFailureIsStillARedirectToTheSpa() throws Exception {
        when(googleLoginFlow.complete("the-code", "the-state", "cookie")).thenThrow(new IllegalStateException("boom"));

        mockMvc.perform(callback("code=the-code&state=the-state").cookie(stateCookie("cookie")))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, SPA + "/login?error=server_error"))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("oauth_state=;"))));
    }

    @Test
    void aCallbackWithNothingInItIsALoginFailure() throws Exception {
        when(googleLoginFlow.complete(isNull(), isNull(), isNull())).thenThrow(new GeneralException(ErrorCode.INVALID_OAUTH_STATE));

        mockMvc.perform(get("/api/v1/auth/oauth2/google/callback"))
                .andExpect(status().isFound())
                .andExpect(header().string(HttpHeaders.LOCATION, SPA + "/login?error=login_failed"));
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder callback(String query) {
        return get("/api/v1/auth/oauth2/google/callback?" + query);
    }

    private static jakarta.servlet.http.Cookie stateCookie(String value) {
        return new jakarta.servlet.http.Cookie("oauth_state", value);
    }
}
