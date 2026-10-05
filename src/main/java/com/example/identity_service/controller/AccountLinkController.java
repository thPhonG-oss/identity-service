package com.example.identity_service.controller;

import com.example.identity_service.config.PendingLinkCookieFactory;
import com.example.identity_service.config.RefreshTokenCookieFactory;
import com.example.identity_service.controller.dto.LinkAccountRequest;
import com.example.identity_service.controller.dto.LoginResponse;
import com.example.identity_service.controller.dto.PendingLinkResponse;
import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.service.authentication.AuthTokens;
import com.example.identity_service.service.oauth2.AccountLinkService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The confirmation step of a sign-in with an external provider whose email belongs to an existing user. These
 * are calls of the SPA's JavaScript, so unlike the redirects of the sign-in itself they answer with JSON.
 *
 * The account waiting for the confirmation is in the {@code oauth_link} cookie, set when the user came back
 * from the provider. The browser does not say which account to link: only the password.
 */
@RestController
@RequestMapping("/api/v1/auth/oauth2/link")
public class AccountLinkController {

    private final AccountLinkService accountLinkService;
    private final PendingLinkCookieFactory linkCookies;
    private final RefreshTokenCookieFactory refreshCookies;

    public AccountLinkController(AccountLinkService accountLinkService, PendingLinkCookieFactory linkCookies,
            RefreshTokenCookieFactory refreshCookies) {
        this.accountLinkService = accountLinkService;
        this.linkCookies = linkCookies;
        this.refreshCookies = refreshCookies;
    }

    /** Which account is waiting, or 401 when nothing is (no cookie, expired, altered). */
    @GetMapping
    public PendingLinkResponse pending(
            @CookieValue(name = PendingLinkCookieFactory.COOKIE_NAME, required = false) String pendingLink) {
        return PendingLinkResponse.from(accountLinkService.pending(pendingLink));
    }

    /** Links the account with the password of the existing one, and signs the user in. */
    @PostMapping
    public ResponseEntity<LoginResponse> link(
            @RequestBody @Valid LinkAccountRequest request,
            @CookieValue(name = PendingLinkCookieFactory.COOKIE_NAME, required = false) String pendingLink,
            @RequestHeader(name = AuthController.CSRF_HEADER, required = false) String csrfHeader) {
        requireCsrfHeader(csrfHeader);

        AuthTokens tokens = accountLinkService.link(pendingLink, request.getPassword());

        // The link is made: the confirmation is spent, and the user has a session like after any login.
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, linkCookies.clear().toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookies.create(tokens.refreshToken()).toString())
                .body(LoginResponse.from(tokens));
    }

    /** The user refuses: nothing was stored, so only the cookie has to go. */
    @PostMapping("/cancel")
    public ResponseEntity<Void> cancel(
            @RequestHeader(name = AuthController.CSRF_HEADER, required = false) String csrfHeader) {
        requireCsrfHeader(csrfHeader);

        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, linkCookies.clear().toString())
                .build();
    }

    private static void requireCsrfHeader(String csrfHeader) {
        if (csrfHeader == null || csrfHeader.isBlank()) {
            throw new GeneralException(ErrorCode.ACCESS_DENIED);
        }
    }
}
