package com.example.identity_service.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;

import com.example.identity_service.model.RefreshCookieProperties;
import com.example.identity_service.model.RefreshCookieProperties.SameSite;

class PendingLinkCookieFactoryTest {

    @Test
    void theCookieIsHttpOnlyStrictScopedToTheLinkEndpointsAndShortLived() {
        PendingLinkCookieFactory factory = new PendingLinkCookieFactory(new RefreshCookieProperties(true, SameSite.STRICT));

        ResponseCookie cookie = factory.create("sealed");

        assertThat(cookie.getName()).isEqualTo("oauth_link");
        assertThat(cookie.getValue()).isEqualTo("sealed");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getSameSite()).isEqualTo("Strict");
        assertThat(cookie.getPath()).isEqualTo("/api/v1/auth/oauth2/link");
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ofMinutes(10));
    }

    // Unlike the state cookie, this one is never needed on a navigation from Google, so it can be Strict
    // whatever the refresh cookie uses.
    @Test
    void sameSiteIsStrictWhateverTheRefreshCookieUses() {
        for (SameSite refreshSameSite : SameSite.values()) {
            assertThat(new PendingLinkCookieFactory(new RefreshCookieProperties(true, refreshSameSite)).create("x").getSameSite())
                    .isEqualTo("Strict");
        }
    }

    @Test
    void secureFollowsTheEnvironment() {
        assertThat(new PendingLinkCookieFactory(new RefreshCookieProperties(false, SameSite.STRICT)).create("x").isSecure())
                .isFalse();
    }

    @Test
    void theDeletingCookieMatchesTheOriginalAndIsAlreadyExpired() {
        PendingLinkCookieFactory factory = new PendingLinkCookieFactory(new RefreshCookieProperties(true, SameSite.STRICT));

        ResponseCookie cleared = factory.clear();

        assertThat(cleared.getName()).isEqualTo(factory.create("x").getName());
        assertThat(cleared.getPath()).isEqualTo(factory.create("x").getPath());
        assertThat(cleared.getValue()).isEmpty();
        assertThat(cleared.getMaxAge()).isEqualTo(Duration.ZERO);
    }
}
