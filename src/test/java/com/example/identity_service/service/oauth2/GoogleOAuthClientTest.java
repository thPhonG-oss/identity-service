package com.example.identity_service.service.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;

// No Google: the token endpoint is a mock server that checks what is sent to it.
class GoogleOAuthClientTest {

    private static final String REDIRECT_URI = "http://localhost:8080/api/v1/auth/oauth2/google/callback";
    private static final String TOKEN_URI = "https://oauth2.googleapis.com/token";

    private final ClientRegistration registration = ClientRegistration.withRegistrationId("google")
            .clientId("my-client-id")
            .clientSecret("my-client-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(REDIRECT_URI)
            .scope("openid", "email", "profile")
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri(TOKEN_URI)
            .build();

    private final RestClient.Builder restClientBuilder = RestClient.builder();
    private final MockRestServiceServer googleServer = MockRestServiceServer.bindTo(restClientBuilder).build();
    private final GoogleOAuthClient client = new GoogleOAuthClient(registration, restClientBuilder.build());

    // ---- the address the browser is sent to ------------------------------------------------------

    @Test
    void theAuthorizationUrlCarriesEverythingGoogleNeeds() {
        String url = client.authorizationUrl("the-state", "the-nonce", "the-challenge");

        MultiValueMap<String, String> query = UriComponentsBuilder.fromUriString(url).build().getQueryParams();
        assertThat(url).startsWith("https://accounts.google.com/o/oauth2/v2/auth?");
        assertThat(decoded(query, "response_type")).isEqualTo("code");
        assertThat(decoded(query, "client_id")).isEqualTo("my-client-id");
        assertThat(decoded(query, "redirect_uri")).isEqualTo(REDIRECT_URI);
        assertThat(Arrays.asList(decoded(query, "scope").split(" "))).containsExactlyInAnyOrder("openid", "email", "profile");
        assertThat(decoded(query, "state")).isEqualTo("the-state");
        assertThat(decoded(query, "nonce")).isEqualTo("the-nonce");
        assertThat(decoded(query, "code_challenge")).isEqualTo("the-challenge");
        assertThat(decoded(query, "code_challenge_method")).isEqualTo("S256");
        assertThat(decoded(query, "prompt")).isEqualTo("select_account");
    }

    @Test
    void theRedirectAddressIsFullyEncodedSoItCannotBreakTheQueryString() {
        String url = client.authorizationUrl("s", "n", "c");

        assertThat(url).contains("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fapi%2Fv1%2Fauth%2Foauth2%2Fgoogle%2Fcallback");
        assertThat(url).contains("scope=").doesNotContain(" ");
    }

    // The URL goes through the user's browser and its history: the secret must never be in it.
    @Test
    void theClientSecretIsNotInTheAuthorizationUrl() {
        assertThat(client.authorizationUrl("s", "n", "c")).doesNotContain("my-client-secret").doesNotContain("secret");
    }

    @Test
    void aValueWithSpecialCharactersIsEncodedNotInterpreted() {
        String url = client.authorizationUrl("a&b=c d", "n", "c");

        MultiValueMap<String, String> query = UriComponentsBuilder.fromUriString(url).build().getQueryParams();
        assertThat(decoded(query, "state")).isEqualTo("a&b=c d");
        assertThat(query.get("b")).isNull(); // it did not become a parameter of its own
    }

    // ---- trading the code for tokens -------------------------------------------------------------

    @Test
    void theCodeIsTradedForTheIdToken() {
        googleServer.expect(requestTo(TOKEN_URI))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(content().formDataContains(Map.of(
                        "grant_type", "authorization_code",
                        "code", "the-code",
                        "redirect_uri", REDIRECT_URI,
                        "client_id", "my-client-id",
                        "client_secret", "my-client-secret",
                        "code_verifier", "the-verifier")))
                .andRespond(withSuccess("{\"id_token\":\"the.id.token\",\"access_token\":\"unused\",\"expires_in\":3599}",
                        MediaType.APPLICATION_JSON));

        assertThat(client.exchangeCode("the-code", "the-verifier")).isEqualTo("the.id.token");
        googleServer.verify();
    }

    @Test
    void aCodeThatGoogleRefusesLetsTheUserTryAgain() {
        googleServer.expect(requestTo(TOKEN_URI)).andRespond(withStatus(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"invalid_grant\",\"error_description\":\"Bad Request\"}"));

        assertFails(ErrorCode.INVALID_OAUTH_STATE);
    }

    // A wrong client id or secret is our mistake, not the user's.
    @Test
    void whenGoogleRejectsThisApplicationItIsAServerError() {
        googleServer.expect(requestTo(TOKEN_URI)).andRespond(withStatus(HttpStatus.UNAUTHORIZED)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"error\":\"invalid_client\",\"error_description\":\"Unauthorized\"}"));

        assertFails(ErrorCode.INTERNAL_ERROR);
    }

    @Test
    void whenGoogleFailsItIsAServerError() {
        googleServer.expect(requestTo(TOKEN_URI)).andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));

        assertFails(ErrorCode.INTERNAL_ERROR);
    }

    @Test
    void whenGoogleCannotBeReachedItIsAServerError() {
        googleServer.expect(requestTo(TOKEN_URI)).andRespond(withException(new IOException("connection refused")));

        assertFails(ErrorCode.INTERNAL_ERROR);
    }

    @Test
    void anAnswerWithoutAnIdTokenIsAServerError() {
        googleServer.expect(requestTo(TOKEN_URI)).andRespond(withSuccess("{\"access_token\":\"only-this\"}", MediaType.APPLICATION_JSON));

        assertFails(ErrorCode.INTERNAL_ERROR);
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private void assertFails(ErrorCode expected) {
        assertThatThrownBy(() -> client.exchangeCode("the-code", "the-verifier"))
                .isInstanceOfSatisfying(GeneralException.class, ex -> assertThat(ex.getErrorCode()).isEqualTo(expected));
    }

    private static String decoded(MultiValueMap<String, String> query, String name) {
        return UriUtils.decode(query.getFirst(name), StandardCharsets.UTF_8);
    }
}
