package com.example.identity_service.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class RefreshTokenPropertiesValidationTest {

    @EnableConfigurationProperties(RefreshTokenProperties.class)
    static class PropertiesConfig {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfig.class);

    @Test
    void theTtlIsReadAsADuration() {
        runner.withPropertyValues("app.security.refresh-token.ttl=7d")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(RefreshTokenProperties.class).ttl()).isEqualTo(Duration.ofDays(7));
                });
    }

    @Test
    void aMissingTtlStopsTheStartup() {
        runner.run(context -> assertThat(context).hasFailed());
    }
}
