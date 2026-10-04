package com.example.identity_service.model;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Settings of the cookie that carries the refresh token, under {@code app.security.refresh-cookie}.
 *
 * @param secure   send the cookie over HTTPS only. Keep it {@code true} everywhere except local
 *                 development over plain http.
 * @param sameSite when the browser attaches the cookie to a request. STRICT only for requests that start
 *                 on the same site (the safest, right when the SPA and this API share a site, e.g.
 *                 app.example.com and api.example.com). NONE is needed only if they are on different
 *                 sites, and then it needs {@code secure}.
 */
@ConfigurationProperties(prefix = "app.security.refresh-cookie")
@Validated
public record RefreshCookieProperties(
        @DefaultValue("true") boolean secure,
        @DefaultValue("STRICT") @NotNull SameSite sameSite) {

    public enum SameSite {
        STRICT("Strict"), LAX("Lax"), NONE("None");

        private final String attributeValue;

        SameSite(String attributeValue) {
            this.attributeValue = attributeValue;
        }

        public String attributeValue() {
            return attributeValue;
        }
    }

    // Browsers ignore a SameSite=None cookie that is not Secure, so that combination can never work.
    @AssertTrue(message = "SameSite NONE requires secure to be true")
    boolean isSecureWhenSameSiteIsNone() {
        return sameSite != SameSite.NONE || secure;
    }
}
