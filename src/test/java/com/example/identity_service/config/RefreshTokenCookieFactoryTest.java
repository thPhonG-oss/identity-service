package com.example.identity_service.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;

import com.example.identity_service.model.RefreshCookieProperties;
import com.example.identity_service.model.RefreshCookieProperties.SameSite;
import com.example.identity_service.model.RefreshTokenProperties;

class RefreshTokenCookieFactoryTest {

    private final RefreshTokenProperties tokenProperties = new RefreshTokenProperties(Duration.ofDays(7));

    @Test
    void theCookieIsHttpOnlyScopedToTheAuthPathAndLivesAsLongAsTheToken() {
        RefreshTokenCookieFactory factory =
                new RefreshTokenCookieFactory(tokenProperties, new RefreshCookieProperties(true, SameSite.STRICT));

        ResponseCookie cookie = factory.create("the-token");

        assertThat(cookie.getName()).isEqualTo("refresh_token");
        assertThat(cookie.getValue()).isEqualTo("the-token");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getSameSite()).isEqualTo("Strict");
        assertThat(cookie.getPath()).isEqualTo("/api/v1/auth");
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ofDays(7));
    }

    @Test
    void secureAndSameSiteFollowTheSettings() {
        RefreshTokenCookieFactory factory =
                new RefreshTokenCookieFactory(tokenProperties, new RefreshCookieProperties(false, SameSite.LAX));

        ResponseCookie cookie = factory.create("the-token");

        assertThat(cookie.isSecure()).isFalse();
        assertThat(cookie.getSameSite()).isEqualTo("Lax");
        assertThat(cookie.isHttpOnly()).isTrue(); // never configurable
    }

    @Test
    void theDeletingCookieMatchesTheOriginalAndIsAlreadyExpired() {
        RefreshTokenCookieFactory factory =
                new RefreshTokenCookieFactory(tokenProperties, new RefreshCookieProperties(true, SameSite.STRICT));

        ResponseCookie cleared = factory.clear();

        // A browser only replaces a cookie when name and path (and domain) are identical.
        assertThat(cleared.getName()).isEqualTo(factory.create("x").getName());
        assertThat(cleared.getPath()).isEqualTo(factory.create("x").getPath());
        assertThat(cleared.getValue()).isEmpty();
        assertThat(cleared.getMaxAge()).isEqualTo(Duration.ZERO);
    }
}
