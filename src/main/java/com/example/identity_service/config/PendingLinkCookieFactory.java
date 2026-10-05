package com.example.identity_service.config;

import com.example.identity_service.model.RefreshCookieProperties;
import com.example.identity_service.service.oauth2.PendingLinkService;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Builds the cookie that holds an external account waiting to be linked (see {@link PendingLinkService}),
 * and the one that deletes it when the link is done or refused.
 *
 * The cookie is sent only to the link endpoints, and with SameSite=Strict: it is used by the SPA's own calls,
 * never by a navigation coming from Google, so no site but ours can make the browser send it.
 */
@Component
public class PendingLinkCookieFactory {

    public static final String COOKIE_NAME = "oauth_link";
    public static final String COOKIE_PATH = "/api/v1/auth/oauth2/link";

    private final RefreshCookieProperties cookieProperties;

    // Only "secure" is taken from the refresh cookie's settings, as for the state cookie.
    public PendingLinkCookieFactory(RefreshCookieProperties cookieProperties) {
        this.cookieProperties = cookieProperties;
    }

    public ResponseCookie create(String value) {
        return build(value, PendingLinkService.LINK_TTL);
    }

    /** Same name and path, empty and already expired, so the browser drops the cookie. */
    public ResponseCookie clear() {
        return build("", Duration.ZERO);
    }

    private ResponseCookie build(String value, Duration maxAge) {
        return ResponseCookie.from(COOKIE_NAME, value)
                .httpOnly(true)
                .secure(cookieProperties.secure())
                .sameSite("Strict")
                .path(COOKIE_PATH)
                .maxAge(maxAge)
                .build();
    }
}
