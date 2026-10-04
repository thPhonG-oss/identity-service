package com.example.identity_service.model;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Settings under {@code app.security.refresh-token}.
 *
 * @param ttl how long a refresh token lives, e.g. {@code 7d}. A token that is used is replaced by a new
 *            one with a fresh lifetime, so an active user stays logged in and an idle one is logged out
 *            after this long.
 */
@ConfigurationProperties(prefix = "app.security.refresh-token")
@Validated
public record RefreshTokenProperties(@NotNull Duration ttl) {
}
