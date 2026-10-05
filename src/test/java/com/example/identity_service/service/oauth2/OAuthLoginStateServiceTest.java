package com.example.identity_service.service.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.JwtProperties;
import com.example.identity_service.service.oauth2.OAuthLoginStateService.PendingLogin;
import com.example.identity_service.service.oauth2.OAuthLoginStateService.ResumedLogin;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

class OAuthLoginStateServiceTest {

    private static final String SECRET = "oauth-state-test-secret-".repeat(3);
    private static final Instant NOW = Instant.parse("2026-10-04T10:00:00Z");

    private final OAuthLoginStateService service = serviceAt(SECRET, NOW);

    // ---- PKCE ------------------------------------------------------------------------------------

    // The example of RFC 7636, appendix B: this verifier must give exactly this challenge.
    @Test
    void theCodeChallengeFollowsTheRfcExample() {
        assertThat(OAuthLoginStateService.codeChallengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
                .isEqualTo("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    // ---- start -----------------------------------------------------------------------------------

    @Test
    void everyLoginGetsItsOwnLongRandomValues() {
        PendingLogin first = service.start(AuthProvider.GOOGLE);
        PendingLogin second = service.start(AuthProvider.GOOGLE);

        assertThat(first.state()).isNotEqualTo(second.state()).hasSize(43).matches("[A-Za-z0-9_-]+");
        assertThat(first.nonce()).isNotEqualTo(second.nonce()).hasSize(43);
        assertThat(first.codeChallenge()).isNotEqualTo(second.codeChallenge());
        assertThat(first.state()).isNotEqualTo(first.nonce());
    }

    @Test
    void theCookieIsEncryptedSoNothingInsideIsReadable() {
        PendingLogin login = service.start(AuthProvider.GOOGLE);

        assertThat(login.cookieValue().split("\\.")).hasSize(5); // a JWE has five parts, a signed JWT three
        assertThat(login.cookieValue()).doesNotContain(login.state()).doesNotContain(login.nonce());
        // the payload part, decoded, is noise: it contains none of the values or the field names
        String ciphertext = new String(java.util.Base64.getUrlDecoder().decode(login.cookieValue().split("\\.")[3]),
                StandardCharsets.ISO_8859_1);
        assertThat(ciphertext).doesNotContain("state").doesNotContain("nonce").doesNotContain("cv");
    }

    // ---- resume ----------------------------------------------------------------------------------

    @Test
    void theCookieGivesBackTheNonceAndAVerifierThatMatchesTheChallenge() {
        PendingLogin login = service.start(AuthProvider.GOOGLE);

        ResumedLogin resumed = service.resume(AuthProvider.GOOGLE, login.cookieValue(), login.state());

        assertThat(resumed.nonce()).isEqualTo(login.nonce());
        // the verifier is the one whose hash was sent to Google as the challenge
        assertThat(OAuthLoginStateService.codeChallengeFor(resumed.codeVerifier())).isEqualTo(login.codeChallenge());
    }

    @Test
    void aStateThatIsNotTheOneInTheCookieIsRejected() {
        PendingLogin login = service.start(AuthProvider.GOOGLE);

        assertRejected(() -> service.resume(AuthProvider.GOOGLE, login.cookieValue(), "state-of-another-login"));
    }

    @Test
    void aMissingCookieOrStateIsRejected() {
        PendingLogin login = service.start(AuthProvider.GOOGLE);

        assertRejected(() -> service.resume(AuthProvider.GOOGLE, null, login.state()));
        assertRejected(() -> service.resume(AuthProvider.GOOGLE, "", login.state()));
        assertRejected(() -> service.resume(AuthProvider.GOOGLE, login.cookieValue(), null));
        assertRejected(() -> service.resume(AuthProvider.GOOGLE, login.cookieValue(), " "));
    }

    @Test
    void anAlteredCookieIsRejected() {
        PendingLogin login = service.start(AuthProvider.GOOGLE);
        String[] parts = login.cookieValue().split("\\.");
        // flip the first character of the ciphertext: AES-GCM notices the change
        String ciphertext = parts[3];
        String changed = (ciphertext.charAt(0) == 'A' ? 'B' : 'A') + ciphertext.substring(1);
        String tampered = parts[0] + "." + parts[1] + "." + parts[2] + "." + changed + "." + parts[4];

        assertRejected(() -> service.resume(AuthProvider.GOOGLE, tampered, login.state()));
    }

    @Test
    void aCookieMadeWithAnotherSecretIsRejected() {
        PendingLogin foreign = serviceAt("another-secret-".repeat(4), NOW).start(AuthProvider.GOOGLE);

        assertRejected(() -> service.resume(AuthProvider.GOOGLE, foreign.cookieValue(), foreign.state()));
    }

    @Test
    void theCookieIsValidForFiveMinutesAndNotLonger() {
        PendingLogin login = service.start(AuthProvider.GOOGLE);

        assertThat(serviceAt(SECRET, NOW.plus(Duration.ofMinutes(4)).plusSeconds(59))
                .resume(AuthProvider.GOOGLE, login.cookieValue(), login.state())).isNotNull();
        assertRejected(() -> serviceAt(SECRET, NOW.plus(Duration.ofMinutes(5)))
                .resume(AuthProvider.GOOGLE, login.cookieValue(), login.state()));
    }

    @Test
    void aCookieMadeForAnotherProviderIsRejected() {
        PendingLogin login = service.start(AuthProvider.GOOGLE);

        assertRejected(() -> service.resume(AuthProvider.GITHUB, login.cookieValue(), login.state()));
    }

    // The same secret signs the access tokens, so the cookie must not be mistaken for one, nor the reverse.
    @Test
    void anAccessTokenCannotStandInForTheCookie() throws Exception {
        SignedJWT accessToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
                .issuer("identity-service").subject("some-user")
                .expirationTime(Date.from(NOW.plusSeconds(600))).claim("state", "x").build());
        accessToken.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));

        assertRejected(() -> service.resume(AuthProvider.GOOGLE, accessToken.serialize(), "x"));
    }

    @Test
    void garbageIsRejected() {
        for (String garbage : new String[] { "abc", "a.b.c", "a.b.c.d.e", "eyJhbGciOiJkaXIifQ...." }) {
            assertRejected(() -> service.resume(AuthProvider.GOOGLE, garbage, "x"));
        }
    }

    @Test
    void valuesNeverRepeatAcrossManyLogins() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            PendingLogin login = service.start(AuthProvider.GOOGLE);
            assertThat(seen.add(login.state())).isTrue();
            assertThat(seen.add(login.nonce())).isTrue();
        }
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private static OAuthLoginStateService serviceAt(String secret, Instant now) {
        return new OAuthLoginStateService(new JwtProperties(secret, Duration.ofMinutes(15)),
                Clock.fixed(now, ZoneOffset.UTC));
    }

    private static void assertRejected(Runnable action) {
        assertThatThrownBy(action::run)
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_OAUTH_STATE));
    }
}
