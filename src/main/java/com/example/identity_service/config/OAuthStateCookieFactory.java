package com.example.identity_service.config;

import com.example.identity_service.model.RefreshCookieProperties;
import com.example.identity_service.service.oauth2.OAuthLoginStateService;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Builds the cookie that carries the login state (see {@link OAuthLoginStateService}) to the browser and
 * back, and the one that deletes it once the login is over.
 *
 * SameSite must be Lax here, not Strict like the refresh cookie. The return from Google is a navigation that
 * starts on accounts.google.com, another site, and a Strict cookie is not sent with it: the callback would
 * never see its state. Lax is sent on exactly that kind of top-level navigation, and not on a request
 * started by another site's script or form.
 */
@Component
public class OAuthStateCookieFactory {

    public static final String COOKIE_NAME = "oauth_state";
    // Every provider's login endpoints live under this path, so the browser sends the cookie only there.
    public static final String COOKIE_PATH = "/api/v1/auth/oauth2";

    private final RefreshCookieProperties cookieProperties;

    // Only "secure" is taken from the refresh cookie's settings: it says whether this environment runs on
    // HTTPS (true) or on plain http in local development (false), which applies to every cookie alike.
    public OAuthStateCookieFactory(RefreshCookieProperties cookieProperties) {
        this.cookieProperties = cookieProperties;
    }

    public ResponseCookie create(String value) {
        return build(value, OAuthLoginStateService.STATE_TTL);
    }

    /** Same name and path, empty and already expired, so the browser drops the cookie. */
    public ResponseCookie clear() {
        return build("", Duration.ZERO);
    }

    private ResponseCookie build(String value, Duration maxAge) {
        return ResponseCookie.from(COOKIE_NAME, value)
                .httpOnly(true)
                .secure(cookieProperties.secure())
                .sameSite("Lax")
                .path(COOKIE_PATH)
                .maxAge(maxAge)
                .build();
    }
}
