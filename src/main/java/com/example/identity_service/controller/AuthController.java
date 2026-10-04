package com.example.identity_service.controller;

import com.example.identity_service.config.RefreshTokenCookieFactory;
import com.example.identity_service.controller.dto.LoginRequest;
import com.example.identity_service.controller.dto.LoginResponse;
import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.dto.request.UserCreationRequest;
import com.example.identity_service.model.dto.response.UserResponse;
import com.example.identity_service.service.authentication.AuthTokens;
import com.example.identity_service.service.authentication.AuthenticationService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("api/v1/auth")
public class AuthController {

    /**
     * Header the SPA must add to the two cookie-authenticated calls (refresh, logout). A page on another
     * origin cannot add a custom header without the browser first asking this API's CORS rules, which
     * only allow our own SPA. So a forged request from a malicious site is refused (CSRF protection).
     */
    public static final String CSRF_HEADER = "X-Requested-With";

    private final AuthenticationService authenticationService;
    private final RefreshTokenCookieFactory refreshTokenCookieFactory;

    public AuthController(AuthenticationService authenticationService, RefreshTokenCookieFactory refreshTokenCookieFactory) {
        this.authenticationService = authenticationService;
        this.refreshTokenCookieFactory = refreshTokenCookieFactory;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest loginRequest) {
        return withTokens(authenticationService.login(loginRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @CookieValue(name = RefreshTokenCookieFactory.COOKIE_NAME, required = false) String refreshToken,
            @RequestHeader(name = CSRF_HEADER, required = false) String csrfHeader) {
        requireCsrfHeader(csrfHeader);
        return withTokens(authenticationService.refresh(refreshToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(name = RefreshTokenCookieFactory.COOKIE_NAME, required = false) String refreshToken,
            @RequestHeader(name = CSRF_HEADER, required = false) String csrfHeader) {
        requireCsrfHeader(csrfHeader);
        authenticationService.logout(refreshToken);
        // Whatever happened above, the browser must forget the cookie.
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookieFactory.clear().toString())
                .build();
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@RequestBody @Valid UserCreationRequest userCreationRequest) {
        return new ResponseEntity<>(
                authenticationService.register(userCreationRequest),
                HttpStatus.CREATED
        );
    }

    // The access token goes in the body for the SPA's JavaScript; the refresh token only in the cookie.
    private ResponseEntity<LoginResponse> withTokens(AuthTokens tokens) {
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookieFactory.create(tokens.refreshToken()).toString())
                .body(LoginResponse.from(tokens));
    }

    private static void requireCsrfHeader(String csrfHeader) {
        if (csrfHeader == null || csrfHeader.isBlank()) {
            throw new GeneralException(ErrorCode.ACCESS_DENIED);
        }
    }
}
