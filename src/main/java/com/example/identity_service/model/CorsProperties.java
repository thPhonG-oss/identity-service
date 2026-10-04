package com.example.identity_service.model;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Browser origins allowed to call this API from JavaScript, under {@code app.security.cors}.
 *
 * @param allowedOrigins exact origins, e.g. {@code https://app.example.com}. Empty means no other origin
 *                       is allowed. There is deliberately no wildcard: the refresh cookie is sent with
 *                       these requests, and browsers refuse a wildcard together with credentials.
 */
@ConfigurationProperties(prefix = "app.security.cors")
public record CorsProperties(@DefaultValue List<String> allowedOrigins) {
}
