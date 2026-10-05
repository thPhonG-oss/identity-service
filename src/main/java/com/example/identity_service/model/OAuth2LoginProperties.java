package com.example.identity_service.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Settings of the login with an external provider (Google, ...), under {@code app.security.oauth2}.
 *
 * @param frontendUrl where the SPA lives, e.g. {@code http://localhost:5173}. After the provider sends the
 *                    user back to this API, the browser is redirected here: to the SPA's home page when the
 *                    login worked, to its login page with an error when it did not. It must be an absolute
 *                    http(s) address. An unset variable leaves the text {@code ${FRONTEND_URL}} as the value,
 *                    which this pattern rejects, so the application refuses to start instead of redirecting
 *                    users to a broken address later.
 */
@ConfigurationProperties(prefix = "app.security.oauth2")
@Validated
public record OAuth2LoginProperties(
        @NotBlank @Pattern(regexp = "^https?://\\S+$", message = "must be an absolute http(s) URL")
        String frontendUrl) {

    /** The address of a page of the SPA, e.g. {@code frontendLocation("/login?error=google")}. */
    public String frontendLocation(String path) {
        String base = frontendUrl.endsWith("/") ? frontendUrl.substring(0, frontendUrl.length() - 1) : frontendUrl;
        return base + (path.startsWith("/") ? path : "/" + path);
    }
}
