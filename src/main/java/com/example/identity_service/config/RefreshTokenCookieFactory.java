package com.example.identity_service.config;

import com.example.identity_service.model.RefreshCookieProperties;
import com.example.identity_service.model.RefreshTokenProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Builds the cookie that carries the refresh token to the browser, and the one that deletes it.
 *
 * HttpOnly makes the cookie invisible to JavaScript, so an XSS bug cannot read the token. Path limits it
 * to the auth endpoints, so the browser does not send it with every API call. Secure and SameSite come
 * from {@link RefreshCookieProperties}.
 */
@Component
public class RefreshTokenCookieFactory {

    public static final String COOKIE_NAME = "refresh_token";
    public static final String COOKIE_PATH = "/api/v1/auth";

    private final RefreshTokenProperties tokenProperties;
    private final RefreshCookieProperties cookieProperties;

    public RefreshTokenCookieFactory(RefreshTokenProperties tokenProperties, RefreshCookieProperties cookieProperties) {
        this.tokenProperties = tokenProperties;
        this.cookieProperties = cookieProperties;
    }

    /** The cookie to set after a login or a refresh. It lives as long as the token does. */
    public ResponseCookie create(String refreshToken) {
        return build(refreshToken, tokenProperties.ttl());
    }

    /** The cookie to set on logout: same name and path, empty, already expired, so the browser drops it. */
    public ResponseCookie clear() {
        return build("", Duration.ZERO);
    }

    private ResponseCookie build(String value, Duration maxAge) {
        return ResponseCookie.from(COOKIE_NAME, value)
                .httpOnly(true)
                .secure(cookieProperties.secure())
                .sameSite(cookieProperties.sameSite().attributeValue())
                .path(COOKIE_PATH)
                .maxAge(maxAge)
                .build();
    }
}
