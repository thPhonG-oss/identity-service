package com.example.identity_service.controller;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.example.identity_service.config.ErrorResponseWriter;
import com.example.identity_service.config.JwtAccessDeniedHandler;
import com.example.identity_service.config.JwtAuthenticationEntryPoint;
import com.example.identity_service.config.PendingLinkCookieFactory;
import com.example.identity_service.config.RefreshTokenCookieFactory;
import com.example.identity_service.config.SecurityConfig;
import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.CorsProperties;
import com.example.identity_service.model.RefreshCookieProperties;
import com.example.identity_service.model.RefreshTokenProperties;
import com.example.identity_service.service.authentication.AuthTokens;
import com.example.identity_service.service.authentication.JwtService;
import com.example.identity_service.service.oauth2.AccountLinkService;
import com.example.identity_service.service.oauth2.ExternalIdentity;

import jakarta.servlet.http.Cookie;

// The real security chain in front of the controller, to see that the endpoints are open to a user who is
// not signed in yet (that is the point of them), and the real cookie factories. The service is mocked.
@WebMvcTest(AccountLinkController.class)
@Import({ SecurityConfig.class, JwtAuthenticationEntryPoint.class, JwtAccessDeniedHandler.class,
        ErrorResponseWriter.class, RefreshTokenCookieFactory.class, PendingLinkCookieFactory.class })
class AccountLinkControllerTest {

    private static final String URL = "/api/v1/auth/oauth2/link";
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
    }

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private AccountLinkService accountLinkService;

    // ---- which account is waiting ----------------------------------------------------------------

    @Test
    void theConfirmationPageLearnsWhichAccountIsWaiting() throws Exception {
        when(accountLinkService.pending("sealed"))
                .thenReturn(new ExternalIdentity(AuthProvider.GOOGLE, "sub-1", "user@gmail.com"));

        mockMvc.perform(get(URL).cookie(linkCookie("sealed")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.provider").value("GOOGLE"))
                .andExpect(jsonPath("$.email").value("user@gmail.com"))
                // the identifier Google gave stays in the cookie
                .andExpect(jsonPath("$.subject").doesNotExist());
    }

    @Test
    void withNothingWaitingTheAnswerIsUnauthorizedNotACrash() throws Exception {
        when(accountLinkService.pending(isNull())).thenThrow(new GeneralException(ErrorCode.INVALID_LINK_REQUEST));

        mockMvc.perform(get(URL))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(ErrorCode.INVALID_LINK_REQUEST.getCode()));
    }

    // ---- the owner confirms ----------------------------------------------------------------------

    @Test
    void confirmingSignsTheUserInAndSpendsTheConfirmation() throws Exception {
        when(accountLinkService.link("sealed", "S3cure-pass!")).thenReturn(new AuthTokens("access-1", "refresh-1", "Bearer", 900));

        mockMvc.perform(link("{\"password\":\"S3cure-pass!\"}").cookie(linkCookie("sealed")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.accessToken").value("access-1"))
                // the refresh token travels only in its cookie
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("refresh_token=refresh-1"))))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("HttpOnly"))))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, hasItem(containsString("oauth_link=;"))));
    }

    @Test
    void aWrongPasswordIsUnauthorizedWithNoSessionAndTheConfirmationIsKeptToTryAgain() throws Exception {
        when(accountLinkService.link(anyString(), anyString())).thenThrow(new GeneralException(ErrorCode.INVALID_CREDENTIALS));

        mockMvc.perform(link("{\"password\":\"wrong\"}").cookie(linkCookie("sealed")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(ErrorCode.INVALID_CREDENTIALS.getCode()))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
    }

    @Test
    void aClashWithAnotherLinkIsAConflict() throws Exception {
        when(accountLinkService.link(anyString(), anyString())).thenThrow(new GeneralException(ErrorCode.IDENTITY_ALREADY_LINKED));

        mockMvc.perform(link("{\"password\":\"S3cure-pass!\"}").cookie(linkCookie("sealed")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(ErrorCode.IDENTITY_ALREADY_LINKED.getCode()));
    }

    @Test
    void aMissingConfirmationReachesTheServiceAsNullAndIsRefusedThere() throws Exception {
        when(accountLinkService.link(isNull(), anyString())).thenThrow(new GeneralException(ErrorCode.INVALID_LINK_REQUEST));

        mockMvc.perform(link("{\"password\":\"S3cure-pass!\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(ErrorCode.INVALID_LINK_REQUEST.getCode()));
    }

    @Test
    void aBlankOrMissingPasswordIsABadRequestAndNothingIsChecked() throws Exception {
        for (String body : new String[] { "{\"password\":\"\"}", "{\"password\":\"   \"}", "{}" }) {
            mockMvc.perform(link(body).cookie(linkCookie("sealed")))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value(ErrorCode.VALIDATION_FAILED.getCode()));
        }

        verifyNoInteractions(accountLinkService);
    }

    // A form or a script of another site cannot add this header without the browser asking our CORS rules first.
    @Test
    void withoutTheCsrfHeaderConfirmingIsForbiddenAndNothingIsChecked() throws Exception {
        mockMvc.perform(post(URL).contentType(MediaType.APPLICATION_JSON).content("{\"password\":\"S3cure-pass!\"}")
                        .cookie(linkCookie("sealed")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(ErrorCode.ACCESS_DENIED.getCode()))
                .andExpect(header().stringValues(HttpHeaders.SET_COOKIE, everyItem(not(containsString("refresh_token")))));

        verify(accountLinkService, never()).link(any(), any());
    }

    // ---- the owner refuses -----------------------------------------------------------------------

    @Test
    void cancellingOnlyDeletesTheCookie() throws Exception {
        mockMvc.perform(post(URL + "/cancel").header(AuthController.CSRF_HEADER, "XMLHttpRequest").cookie(linkCookie("sealed")))
                .andExpect(status().isNoContent())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("oauth_link=;")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));

        verifyNoInteractions(accountLinkService);
    }

    @Test
    void cancellingNeedsTheCsrfHeaderToo() throws Exception {
        mockMvc.perform(post(URL + "/cancel").cookie(linkCookie("sealed")))
                .andExpect(status().isForbidden());
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private static MockHttpServletRequestBuilder link(String body) {
        return post(URL).contentType(MediaType.APPLICATION_JSON).content(body)
                .header(AuthController.CSRF_HEADER, "XMLHttpRequest");
    }

    private static Cookie linkCookie(String value) {
        return new Cookie("oauth_link", value);
    }
}
