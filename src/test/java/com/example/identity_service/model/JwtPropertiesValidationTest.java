package com.example.identity_service.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

// Checks that a bad JWT configuration stops the application at startup instead of at the first login.
class JwtPropertiesValidationTest {

    @EnableConfigurationProperties(JwtProperties.class)
    static class PropertiesConfig {
    }

    private static final String VALID_SECRET = "a-secret-that-is-at-least-32-bytes!";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfig.class);

    @Test
    void validConfigurationStarts() {
        runner.withPropertyValues(
                "app.security.jwt.secret=" + VALID_SECRET,
                "app.security.jwt.access-token-ttl=15m")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    JwtProperties properties = context.getBean(JwtProperties.class);
                    assertThat(properties.secret()).isEqualTo(VALID_SECRET);
                    assertThat(properties.accessTokenTtl()).isEqualTo(Duration.ofMinutes(15));
                });
    }

    @Test
    void secretShorterThan32CharactersStopsTheStartup() {
        runner.withPropertyValues(
                "app.security.jwt.secret=" + "x".repeat(31),
                "app.security.jwt.access-token-ttl=15m")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void missingSecretStopsTheStartup() {
        runner.withPropertyValues("app.security.jwt.access-token-ttl=15m")
                .run(context -> assertThat(context).hasFailed());
    }

    // An unset JWT_SECRET leaves the literal text "${JWT_SECRET}" as the value; it is only 13 characters.
    @Test
    void unresolvedPlaceholderIsCaughtBecauseItIsShort() {
        runner.withPropertyValues(
                "app.security.jwt.secret=${JWT_SECRET_THAT_IS_NOT_SET}",
                "app.security.jwt.access-token-ttl=15m")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void missingTtlStopsTheStartup() {
        runner.withPropertyValues("app.security.jwt.secret=" + VALID_SECRET)
                .run(context -> assertThat(context).hasFailed());
    }
}
