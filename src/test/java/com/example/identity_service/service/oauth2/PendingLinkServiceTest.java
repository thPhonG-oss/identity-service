package com.example.identity_service.service.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.JwtProperties;

class PendingLinkServiceTest {

    private static final String SECRET = "pending-link-test-secret-".repeat(2);
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    private final JwtProperties properties = new JwtProperties(SECRET, Duration.ofMinutes(15));
    private final PendingLinkService service = new PendingLinkService(properties, Clock.fixed(NOW, ZoneOffset.UTC));
    private final ExternalIdentity identity = new ExternalIdentity(AuthProvider.GOOGLE, "sub-1", "user@gmail.com");

    @Test
    void theIdentityComesBackAsItWentIn() {
        assertThat(service.resume(service.start(identity))).isEqualTo(identity);
    }

    // The browser holds the cookie but must not be able to read what Google said about the user.
    @Test
    void theCookieDoesNotShowTheIdentity() {
        String cookie = service.start(identity);

        assertThat(cookie).doesNotContain("sub-1").doesNotContain("user@gmail.com");
        assertThat(cookie.split("\\.")).hasSize(5); // a JWE: header, key, iv, ciphertext, tag
    }

    @Test
    void itIsValidForTheTimeToConfirmAndNotAfter() {
        String cookie = service.start(identity);

        PendingLinkService justBefore = at(NOW.plus(PendingLinkService.LINK_TTL).minusSeconds(1));
        PendingLinkService atTheEnd = at(NOW.plus(PendingLinkService.LINK_TTL));

        assertThat(justBefore.resume(cookie)).isEqualTo(identity);
        assertRejected(() -> atTheEnd.resume(cookie));
    }

    @Test
    void missingOrBlankIsRejected() {
        assertRejected(() -> service.resume(null));
        assertRejected(() -> service.resume(""));
        assertRejected(() -> service.resume("   "));
    }

    @Test
    void garbageAndTamperedValuesAreRejected() {
        String cookie = service.start(identity);
        String[] parts = cookie.split("\\.");
        String tampered = parts[0] + "." + parts[1] + "." + parts[2] + "." + flip(parts[3]) + "." + parts[4];

        assertRejected(() -> service.resume("not-a-token"));
        assertRejected(() -> service.resume("a.b.c.d.e"));
        assertRejected(() -> service.resume(tampered));
    }

    @Test
    void aCookieMadeWithAnotherSecretIsRejected() {
        PendingLinkService other = new PendingLinkService(
                new JwtProperties("some-other-secret-".repeat(3), Duration.ofMinutes(15)), Clock.fixed(NOW, ZoneOffset.UTC));

        assertRejected(() -> service.resume(other.start(identity)));
    }

    // The same secret, but the state of the login itself is sealed for another purpose: it must not pass for
    // a confirmation, or a login that only just started could be turned into a link.
    @Test
    void theStateCookieOfALoginCannotStandInForAConfirmation() {
        OAuthLoginStateService stateService = new OAuthLoginStateService(properties, Clock.fixed(NOW, ZoneOffset.UTC));
        String stateCookie = stateService.start(AuthProvider.GOOGLE).cookieValue();

        assertRejected(() -> service.resume(stateCookie));
    }

    // And the reverse, for a sealed value that even has all the right fields.
    @Test
    void aValueSealedForAnotherPurposeWithTheRightFieldsIsRejected() {
        JweSealer foreign = new JweSealer(SECRET, "identity-service:something-else");
        String forged = foreign.seal(Map.of("purpose", "link", "provider", "GOOGLE", "sub", "sub-1",
                "email", "victim@gmail.com", "exp", NOW.plusSeconds(60).getEpochSecond()));

        assertRejected(() -> service.resume(forged));
    }

    @Test
    void aValueWithTheRightKeyButThePurposeMissingOrWrongIsRejected() {
        JweSealer sealer = new JweSealer(SECRET, "identity-service:oauth2-pending-link-cookie");
        long exp = NOW.plusSeconds(60).getEpochSecond();

        assertRejected(() -> service.resume(sealer.seal(Map.of("provider", "GOOGLE", "sub", "s", "email", "e@x.com", "exp", exp))));
        assertRejected(() -> service.resume(sealer.seal(Map.of("purpose", "state", "provider", "GOOGLE", "sub", "s", "email", "e@x.com", "exp", exp))));
        assertRejected(() -> service.resume(sealer.seal(Map.of("purpose", "link", "provider", "FACEBOOK", "sub", "s", "email", "e@x.com", "exp", exp))));
        assertRejected(() -> service.resume(sealer.seal(Map.of("purpose", "link", "provider", "GOOGLE", "sub", "s", "exp", exp))));
        assertRejected(() -> service.resume(sealer.seal(Map.of("purpose", "link", "provider", "GOOGLE", "sub", "s", "email", "e@x.com"))));
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private PendingLinkService at(Instant instant) {
        return new PendingLinkService(properties, Clock.fixed(instant, ZoneOffset.UTC));
    }

    private static String flip(String base64Url) {
        char first = base64Url.charAt(0);
        return (first == 'A' ? 'B' : 'A') + base64Url.substring(1);
    }

    private static void assertRejected(Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(GeneralException.class,
                ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_LINK_REQUEST));
    }
}
