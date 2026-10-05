package com.example.identity_service.config;

import com.example.identity_service.service.oauth2.GoogleIdTokenVerifier;
import com.example.identity_service.service.oauth2.GoogleOAuthClient;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.client.RestClient;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

// Google's addresses, this application's client id and secret, and the redirect address all come from the
// "google" registration in application.yaml (spring.security.oauth2.client.registration.google), so each of
// them exists in one place only.
@Slf4j
@Configuration
public class GoogleOAuthConfig {

    @Bean
    public GoogleIdTokenVerifier googleIdTokenVerifier(ClientRegistrationRepository registrations)
            throws MalformedURLException {
        ClientRegistration google = googleRegistration(registrations);

        // Google's public keys, downloaded when needed and kept for a while. Short timeouts, so a slow
        // Google cannot hang a login. If a download fails the keys already known are still used.
        JWKSource<SecurityContext> keys = JWKSourceBuilder
                .<SecurityContext>create(
                        URI.create(google.getProviderDetails().getJwkSetUri()).toURL(),
                        new DefaultResourceRetriever(2_000, 2_000, 64 * 1024))
                .retrying(true)
                .outageTolerant(true)
                .build();

        return new GoogleIdTokenVerifier(keys, google.getClientId());
    }

    @Bean
    public GoogleOAuthClient googleOAuthClient(ClientRegistrationRepository registrations) {
        ClientRegistration google = googleRegistration(registrations);

        String redirectUri = google.getRedirectUri();
        if (redirectUri == null || redirectUri.contains("{") || !redirectUri.startsWith("http")) {
            // Unset, or still the unexpanded template. Google refuses any address it was not given exactly.
            log.warn("The redirect address of the google registration is not a complete URL: login with Google will not work");
        }

        // Timeouts, so a slow Google cannot hang a login.
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build());
        requestFactory.setReadTimeout(Duration.ofSeconds(5));

        return new GoogleOAuthClient(google, RestClient.builder().requestFactory(requestFactory).build());
    }

    private ClientRegistration googleRegistration(ClientRegistrationRepository registrations) {
        ClientRegistration google = registrations.findByRegistrationId("google");
        if (google == null) {
            throw new IllegalStateException("No client registration named 'google' in application.yaml");
        }

        String clientId = google.getClientId();
        if (clientId == null || clientId.isBlank() || clientId.startsWith("${")) {
            // An unset GOOGLE_CLIENT_ID is left as the text "${GOOGLE_CLIENT_ID}". The beans are still built, and
            // since no real token names that audience, every login fails closed instead of the whole
            // application refusing to start in an environment that has no Google credentials.
            log.warn("GOOGLE_CLIENT_ID is not set: login with Google will not work");
        }
        return google;
    }
}
