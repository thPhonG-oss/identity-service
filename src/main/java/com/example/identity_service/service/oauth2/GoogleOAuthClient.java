package com.example.identity_service.service.oauth2;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

/**
 * The two things this application says to Google in the Authorization Code flow:
 * the address the user's browser is sent to, and the request that trades the returned code for tokens.
 *
 * Google's addresses, the client id and secret and the redirect address all come from the "google"
 * registration in application.yaml, so each of them is written in one place only.
 */
@Slf4j
public class GoogleOAuthClient {

    private final ClientRegistration registration;
    private final RestClient restClient;

    public GoogleOAuthClient(ClientRegistration registration, RestClient restClient) {
        this.registration = registration;
        this.restClient = restClient;
    }

    /**
     * The address to send the browser to, where the user logs in at Google and agrees to share their email.
     *
     * @param state         comes back unchanged on the return trip, to prove it belongs to this login
     * @param nonce         copied by Google into the ID token, to tie that token to this login
     * @param codeChallenge the hash of the PKCE code verifier, which is needed again to trade the code
     */
    public String authorizationUrl(String state, String nonce, String codeChallenge) {
        // Every value goes through a URI template variable: the builder then encodes it completely, so
        // characters such as ':' and '/' in the redirect address cannot break the query string.
        return UriComponentsBuilder.fromUriString(registration.getProviderDetails().getAuthorizationUri())
                .queryParam("response_type", "code")
                .queryParam("client_id", "{clientId}")
                .queryParam("redirect_uri", "{redirectUri}")
                .queryParam("scope", "{scope}")
                .queryParam("state", "{state}")
                .queryParam("nonce", "{nonce}")
                .queryParam("code_challenge", "{codeChallenge}")
                .queryParam("code_challenge_method", "S256")
                // always let the user pick the Google account, instead of silently using the one signed in
                .queryParam("prompt", "select_account")
                .encode()
                .buildAndExpand(Map.of(
                        "clientId", registration.getClientId(),
                        "redirectUri", registration.getRedirectUri(),
                        "scope", String.join(" ", registration.getScopes()),
                        "state", state,
                        "nonce", nonce,
                        "codeChallenge", codeChallenge))
                .toUriString();
    }

    /**
     * Trades the authorization code for tokens and returns the ID token.
     *
     * The call goes from this server to Google, so the client secret and the PKCE verifier never pass
     * through the browser.
     *
     * @throws GeneralException INVALID_OAUTH_STATE when Google refuses the code (expired, already used,
     *                          or not for this verifier): the user can simply try again.
     *                          INTERNAL_ERROR when Google cannot be reached or rejects this application
     *                          itself (wrong client id or secret): the user did nothing wrong.
     */
    public String exchangeCode(String code, String codeVerifier) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", registration.getRedirectUri());
        form.add("client_id", registration.getClientId());
        form.add("client_secret", registration.getClientSecret());
        form.add("code_verifier", codeVerifier);

        try {
            Map<String, Object> response = restClient.post()
                    .uri(registration.getProviderDetails().getTokenUri())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(form)
                    .retrieve()
                    .body(new ParameterizedTypeReference<Map<String, Object>>() {
                    });

            if (response != null && response.get("id_token") instanceof String idToken && !idToken.isBlank()) {
                return idToken;
            }
            log.error("Google's token endpoint answered without an id_token");
            throw new GeneralException(ErrorCode.INTERNAL_ERROR);
        } catch (HttpClientErrorException e) {
            // The body is logged only as the error code Google gives: it never holds a secret, but the
            // request that caused it did, so the request is not logged at all.
            if (e.getResponseBodyAsString().contains("invalid_grant")) {
                log.warn("Google refused the authorization code (invalid_grant)");
                throw new GeneralException(ErrorCode.INVALID_OAUTH_STATE);
            }
            log.error("Google rejected this application's token request: status {}", e.getStatusCode().value());
            throw new GeneralException(ErrorCode.INTERNAL_ERROR);
        } catch (RestClientException e) {
            log.error("Could not reach Google's token endpoint", e);
            throw new GeneralException(ErrorCode.INTERNAL_ERROR);
        }
    }
}
