package com.example.identity_service.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class RefreshCookiePropertiesValidationTest {

    @EnableConfigurationProperties({ RefreshCookieProperties.class, CorsProperties.class })
    static class PropertiesConfig {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfig.class);

    @Test
    void theDefaultsAreTheSafestOnes() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            RefreshCookieProperties properties = context.getBean(RefreshCookieProperties.class);
            assertThat(properties.secure()).isTrue();
            assertThat(properties.sameSite()).isEqualTo(RefreshCookieProperties.SameSite.STRICT);
        });
    }

    @Test
    void theSettingsAreRead() {
        runner.withPropertyValues("app.security.refresh-cookie.secure=false", "app.security.refresh-cookie.same-site=lax")
                .run(context -> {
                    RefreshCookieProperties properties = context.getBean(RefreshCookieProperties.class);
                    assertThat(properties.secure()).isFalse();
                    assertThat(properties.sameSite()).isEqualTo(RefreshCookieProperties.SameSite.LAX);
                });
    }

    // Browsers drop a SameSite=None cookie that is not Secure, so the application refuses to start.
    @Test
    void sameSiteNoneWithoutSecureStopsTheStartup() {
        runner.withPropertyValues("app.security.refresh-cookie.secure=false", "app.security.refresh-cookie.same-site=none")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void sameSiteNoneWithSecureIsAccepted() {
        runner.withPropertyValues("app.security.refresh-cookie.secure=true", "app.security.refresh-cookie.same-site=none")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void noCorsOriginsAreAllowedByDefault() {
        runner.run(context -> assertThat(context.getBean(CorsProperties.class).allowedOrigins()).isEmpty());
    }

    @Test
    void allowedOriginsAreReadAsAList() {
        runner.withPropertyValues("app.security.cors.allowed-origins=https://a.example.com,https://b.example.com")
                .run(context -> assertThat(context.getBean(CorsProperties.class).allowedOrigins())
                        .isEqualTo(List.of("https://a.example.com", "https://b.example.com")));
    }
}
