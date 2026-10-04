package com.example.identity_service.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@ConfigurationProperties(prefix = "app.security.jwt")
@Validated
public record JwtProperties (
    @NotBlank @Size(min = 32) String secret,
    @NotNull Duration accessTokenTtl
) {}
