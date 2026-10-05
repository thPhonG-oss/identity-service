package com.example.identity_service.model;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class OAuth2LoginPropertiesValidationTest {

    @EnableConfigurationProperties(OAuth2LoginProperties.class)
    static class PropertiesConfig {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfig.class);

    @Test
    void anAbsoluteHttpAddressIsAccepted() {
        runner.withPropertyValues("app.security.oauth2.frontend-url=http://localhost:5173")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(OAuth2LoginProperties.class).frontendUrl()).isEqualTo("http://localhost:5173");
                });
    }

    @Test
    void anHttpsAddressWithAPathIsAccepted() {
        runner.withPropertyValues("app.security.oauth2.frontend-url=https://example.com/app")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void aMissingAddressStopsTheStartup() {
        runner.run(context -> assertThat(context).hasFailed());
    }

    // What an unset FRONTEND_URL leaves behind: the placeholder as plain text.
    @Test
    void anUnresolvedPlaceholderStopsTheStartup() {
        runner.withPropertyValues("app.security.oauth2.frontend-url=${FRONTEND_URL_NOT_SET}")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void anAddressWithoutAnHttpSchemeStopsTheStartup() {
        runner.withPropertyValues("app.security.oauth2.frontend-url=localhost:5173")
                .run(context -> assertThat(context).hasFailed());
        runner.withPropertyValues("app.security.oauth2.frontend-url=javascript:alert(1)")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void pagesAreBuiltWithoutADoubleSlash() {
        assertThat(new OAuth2LoginProperties("http://localhost:5173").frontendLocation("/login?error=google"))
                .isEqualTo("http://localhost:5173/login?error=google");
        assertThat(new OAuth2LoginProperties("http://localhost:5173/").frontendLocation("/"))
                .isEqualTo("http://localhost:5173/");
        assertThat(new OAuth2LoginProperties("https://example.com/app").frontendLocation("login"))
                .isEqualTo("https://example.com/app/login");
    }
}
