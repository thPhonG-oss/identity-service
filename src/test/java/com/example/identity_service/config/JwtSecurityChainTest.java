package com.example.identity_service.config;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import jakarta.servlet.http.Cookie;
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

import com.example.identity_service.controller.AuthController;
import com.example.identity_service.controller.RoleController;
import com.example.identity_service.controller.UserController;
import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.CorsProperties;
import com.example.identity_service.model.JwtUser;
import com.example.identity_service.model.RefreshCookieProperties;
import com.example.identity_service.model.RefreshTokenProperties;
import com.example.identity_service.model.dto.response.UserResponse;
import com.example.identity_service.service.RoleService;
import com.example.identity_service.service.UserService;
import com.example.identity_service.service.authentication.AuthTokens;
import com.example.identity_service.service.authentication.AuthenticationService;
import com.example.identity_service.service.authentication.JwtService;

// The real security chain (SecurityConfig, the filter, the entry point and the access denied handler) in
// front of real controllers. Only the services behind them are mocked, so no database is needed.
@WebMvcTest({ UserController.class, AuthController.class, RoleController.class })
@Import({ SecurityConfig.class, JwtAuthenticationEntryPoint.class, JwtAccessDeniedHandler.class,
        ErrorResponseWriter.class, RefreshTokenCookieFactory.class })
class JwtSecurityChainTest {

    private static final String SPA_ORIGIN = "https://app.example.com";

    // A WebMvcTest does not scan @ConfigurationProperties classes, so the settings are given directly.
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
            return new CorsProperties(List.of(SPA_ORIGIN));
        }
    }

    private static final String USER_URL = "/api/v1/users/{id}";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private RoleService roleService;

    @MockitoBean
    private AuthenticationService authenticationService;

    // ---- 401: no (usable) credentials ------------------------------------------------------------

    @Test
    void protectedEndpointWithoutATokenIs401Unauthenticated() throws Exception {
        mockMvc.perform(get(USER_URL, UUID.randomUUID()))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"))
                .andExpect(jsonPath("$.code").value(ErrorCode.UNAUTHENTICATED.getCode()));
    }

    @Test
    void anExpiredTokenIs401WithTheExpiredCode() throws Exception {
        when(jwtService.getUserFromToken("old-token")).thenThrow(new GeneralException(ErrorCode.TOKEN_EXPIRED));

        mockMvc.perform(get(USER_URL, UUID.randomUUID()).header("Authorization", "Bearer old-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", org.hamcrest.Matchers.containsString("invalid_token")))
                .andExpect(jsonPath("$.code").value(ErrorCode.TOKEN_EXPIRED.getCode()));
    }

    @Test
    void aRejectedTokenIs401WithTheInvalidCode() throws Exception {
        when(jwtService.getUserFromToken("bad-token")).thenThrow(new GeneralException(ErrorCode.INVALID_TOKEN));

        mockMvc.perform(get(USER_URL, UUID.randomUUID()).header("Authorization", "Bearer bad-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(ErrorCode.INVALID_TOKEN.getCode()));
    }

    @Test
    void anotherAuthenticationSchemeIsTreatedAsNoCredentials() throws Exception {
        mockMvc.perform(get(USER_URL, UUID.randomUUID()).header("Authorization", "Basic dXNlcjpwYXNz"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(ErrorCode.UNAUTHENTICATED.getCode()));
    }

    // ---- a user reads user data: own data yes, other people's no, admin anyone's -----------------

    @Test
    void aUserCanReadTheirOwnData() throws Exception {
        UUID userId = UUID.randomUUID();
        when(jwtService.getUserFromToken("user-token")).thenReturn(new JwtUser(userId, List.of("ROLE_USER")));
        when(userService.getUserInfo(userId)).thenReturn(userResponse(userId, "phong@example.com"));

        mockMvc.perform(get(USER_URL, userId).header("Authorization", "Bearer user-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("phong@example.com"));
    }

    @Test
    void aUserCannotReadSomeoneElsesData() throws Exception {
        when(jwtService.getUserFromToken("user-token"))
                .thenReturn(new JwtUser(UUID.randomUUID(), List.of("ROLE_USER")));

        mockMvc.perform(get(USER_URL, UUID.randomUUID()).header("Authorization", "Bearer user-token"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(ErrorCode.ACCESS_DENIED.getCode()));
    }

    @Test
    void anAdminCanReadAnyonesData() throws Exception {
        UUID someoneElse = UUID.randomUUID();
        when(jwtService.getUserFromToken("admin-token"))
                .thenReturn(new JwtUser(UUID.randomUUID(), List.of("ROLE_USER", "ROLE_ADMIN")));
        when(userService.getUserInfo(someoneElse)).thenReturn(userResponse(someoneElse, "other@example.com"));

        mockMvc.perform(get(USER_URL, someoneElse).header("Authorization", "Bearer admin-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("other@example.com"));
    }

    // ---- 403 from a URL rule: handled by JwtAccessDeniedHandler ----------------------------------

    @Test
    void aUserWithoutTheAdminRoleGets403OnTheRolesEndpoints() throws Exception {
        when(jwtService.getUserFromToken("user-token"))
                .thenReturn(new JwtUser(UUID.randomUUID(), List.of("ROLE_USER")));

        mockMvc.perform(get("/api/v1/roles").header("Authorization", "Bearer user-token"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.code").value(ErrorCode.ACCESS_DENIED.getCode()))
                .andExpect(jsonPath("$.path").value("/api/v1/roles"));
    }

    @Test
    void anAdminCanListRoles() throws Exception {
        when(jwtService.getUserFromToken("admin-token"))
                .thenReturn(new JwtUser(UUID.randomUUID(), List.of("ROLE_ADMIN")));
        when(roleService.getAllRoles()).thenReturn(List.of());

        mockMvc.perform(get("/api/v1/roles").header("Authorization", "Bearer admin-token"))
                .andExpect(status().isOk());
    }

    @Test
    void theRolesEndpointsStillNeedAuthenticationFirst() throws Exception {
        mockMvc.perform(get("/api/v1/roles"))
                .andExpect(status().isUnauthorized());
    }

    // ---- public endpoints ------------------------------------------------------------------------

    @Test
    void publicEndpointsIgnoreAnExpiredToken() throws Exception {
        when(jwtService.getUserFromToken("old-token")).thenThrow(new GeneralException(ErrorCode.TOKEN_EXPIRED));
        when(authenticationService.register(any())).thenReturn(userResponse(UUID.randomUUID(), "new@example.com"));

        mockMvc.perform(post("/api/v1/auth/register")
                        .header("Authorization", "Bearer old-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"new@example.com\",\"password\":\"S3cure-pass!\"}"))
                .andExpect(status().isCreated());
    }

    @Test
    void loginIsPublicReturnsTheAccessTokenInTheBodyAndTheRefreshTokenOnlyInACookie() throws Exception {
        when(authenticationService.login(any()))
                .thenReturn(new AuthTokens("the-access-token", "the-refresh-token", "Bearer", 900));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"phong@example.com\",\"password\":\"S3cure-pass!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.accessToken").value("the-access-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                // JavaScript must never be able to read the refresh token
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("refresh_token=the-refresh-token")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("HttpOnly")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Secure")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("SameSite=Strict")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Path=/api/v1/auth")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=604800")));
    }

    @Test
    void loginRejectsABlankBodyBeforeReachingTheService() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"\",\"password\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(ErrorCode.VALIDATION_FAILED.getCode()));
    }

    @Test
    void wrongCredentialsAreReportedAs401() throws Exception {
        when(authenticationService.login(any())).thenThrow(new GeneralException(ErrorCode.INVALID_CREDENTIALS));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"phong@example.com\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(ErrorCode.INVALID_CREDENTIALS.getCode()))
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    // ---- refresh token: carried in a cookie -----------------------------------------------------

    @Test
    void refreshReadsTheCookieAndReplacesIt() throws Exception {
        when(jwtService.getUserFromToken("old-token")).thenThrow(new GeneralException(ErrorCode.TOKEN_EXPIRED));
        when(authenticationService.refresh("the-old-refresh"))
                .thenReturn(new AuthTokens("new-access", "new-refresh", "Bearer", 900));

        // The access token is expired, which is the whole reason for refreshing, so it must not block this.
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .header("Authorization", "Bearer old-token")
                        .header(AuthController.CSRF_HEADER, "XMLHttpRequest")
                        .cookie(new Cookie("refresh_token", "the-old-refresh")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access"))
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("refresh_token=new-refresh")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("HttpOnly")));
    }

    @Test
    void refreshWithoutTheCsrfHeaderIsRefusedBeforeTheTokenIsTouched() throws Exception {
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(new Cookie("refresh_token", "the-old-refresh")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(ErrorCode.ACCESS_DENIED.getCode()));

        verify(authenticationService, never()).refresh(any());
    }

    @Test
    void refreshWithoutTheCookieIs401() throws Exception {
        when(authenticationService.refresh(isNull())).thenThrow(new GeneralException(ErrorCode.INVALID_REFRESH_TOKEN));

        mockMvc.perform(post("/api/v1/auth/refresh").header(AuthController.CSRF_HEADER, "XMLHttpRequest"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(ErrorCode.INVALID_REFRESH_TOKEN.getCode()));
    }

    @Test
    void aRefreshTokenThatIsNotAcceptedIs401() throws Exception {
        when(authenticationService.refresh("stolen-or-old"))
                .thenThrow(new GeneralException(ErrorCode.INVALID_REFRESH_TOKEN));

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .header(AuthController.CSRF_HEADER, "XMLHttpRequest")
                        .cookie(new Cookie("refresh_token", "stolen-or-old")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(ErrorCode.INVALID_REFRESH_TOKEN.getCode()));
    }

    @Test
    void logoutRevokesTheTokenAndDeletesTheCookie() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout")
                        .header(AuthController.CSRF_HEADER, "XMLHttpRequest")
                        .cookie(new Cookie("refresh_token", "the-refresh-token")))
                .andExpect(status().isNoContent())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("refresh_token=;")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")))
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Path=/api/v1/auth")));

        verify(authenticationService).logout("the-refresh-token");
    }

    @Test
    void logoutWithoutTheCsrfHeaderIsRefused() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout").cookie(new Cookie("refresh_token", "the-refresh-token")))
                .andExpect(status().isForbidden());

        verify(authenticationService, never()).logout(any());
    }

    // ---- CORS: the SPA runs on another origin ----------------------------------------------------

    @Test
    void thePreflightFromTheSpaOriginIsAnsweredAndAllowsCredentials() throws Exception {
        mockMvc.perform(options("/api/v1/auth/refresh")
                        .header(HttpHeaders.ORIGIN, SPA_ORIGIN)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "x-requested-with"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, SPA_ORIGIN))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
    }

    @Test
    void thePreflightFromAnotherOriginIsRefused() throws Exception {
        mockMvc.perform(options("/api/v1/auth/refresh")
                        .header(HttpHeaders.ORIGIN, "https://evil.example.com")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "x-requested-with"))
                .andExpect(status().isForbidden());
    }

    private static UserResponse userResponse(UUID id, String email) {
        UserResponse response = new UserResponse();
        response.setId(id.toString());
        response.setEmail(email);
        return response;
    }
}
