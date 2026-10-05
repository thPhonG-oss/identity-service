package com.example.identity_service.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;

import com.example.identity_service.model.RefreshCookieProperties;
import com.example.identity_service.model.RefreshCookieProperties.SameSite;

class OAuthStateCookieFactoryTest {

    @Test
    void theCookieIsHttpOnlyLaxScopedToTheOAuthPathAndShortLived() {
        OAuthStateCookieFactory factory = new OAuthStateCookieFactory(new RefreshCookieProperties(true, SameSite.STRICT));

        ResponseCookie cookie = factory.create("encrypted-state");

        assertThat(cookie.getName()).isEqualTo("oauth_state");
        assertThat(cookie.getValue()).isEqualTo("encrypted-state");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getPath()).isEqualTo("/api/v1/auth/oauth2");
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ofMinutes(5));
    }

    // Strict would not be sent when Google redirects the browser back, which would break every login.
    @Test
    void sameSiteIsLaxWhateverTheRefreshCookieUses() {
        for (SameSite refreshSameSite : SameSite.values()) {
            OAuthStateCookieFactory factory = new OAuthStateCookieFactory(new RefreshCookieProperties(true, refreshSameSite));

            assertThat(factory.create("x").getSameSite()).isEqualTo("Lax");
        }
    }

    @Test
    void secureFollowsTheEnvironment() {
        assertThat(new OAuthStateCookieFactory(new RefreshCookieProperties(false, SameSite.STRICT)).create("x").isSecure())
                .isFalse();
    }

    @Test
    void theDeletingCookieMatchesTheOriginalAndIsAlreadyExpired() {
        OAuthStateCookieFactory factory = new OAuthStateCookieFactory(new RefreshCookieProperties(true, SameSite.STRICT));

        ResponseCookie cleared = factory.clear();

        // A browser only replaces a cookie when name and path are identical.
        assertThat(cleared.getName()).isEqualTo(factory.create("x").getName());
        assertThat(cleared.getPath()).isEqualTo(factory.create("x").getPath());
        assertThat(cleared.getValue()).isEmpty();
        assertThat(cleared.getMaxAge()).isEqualTo(Duration.ZERO);
    }
}
