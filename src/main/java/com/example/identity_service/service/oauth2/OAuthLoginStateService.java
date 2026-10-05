package com.example.identity_service.service.oauth2;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.JwtProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Keeps what a login with an external provider must remember between its two halves.
 *
 * The login goes in two steps: the browser is sent to Google, and later Google sends it back with a
 * {@code code}. This server holds no session, so what it must remember in between travels in a cookie, as
 * an encrypted token (JWE). It holds three values:
 * <ul>
 *   <li><b>state</b>: a random value sent to Google and returned by it. If the value that comes back is not
 *       the one in the cookie, the request did not start from this browser (CSRF on the login).</li>
 *   <li><b>nonce</b>: a random value Google copies into the ID token. Compared with the token's, it ties
 *       that token to this login, so a token captured elsewhere cannot be replayed.</li>
 *   <li><b>code_verifier</b> (PKCE): a secret whose hash (the code challenge) goes to Google. Exchanging the
 *       code needs the verifier, so a stolen code is useless to whoever lacks it.</li>
 * </ul>
 *
 * Encrypted rather than only signed, because the code verifier is a secret: a signed token would still let
 * anyone who sees the cookie read it.
 */
@Slf4j
@Service
public class OAuthLoginStateService {

    /** A login must be finished within this time. */
    public static final Duration STATE_TTL = Duration.ofMinutes(5);

    // 32 random bytes are 43 characters of Base64URL, the shortest verifier RFC 7636 allows.
    private static final int RANDOM_BYTES = 32;

    private final SecureRandom secureRandom = new SecureRandom();
    private final JweSealer sealer;
    private final Clock clock;

    /**
     * @param jwtProperties only the secret is used, to derive a key of its own for this purpose
     */
    public OAuthLoginStateService(JwtProperties jwtProperties, Clock clock) {
        this.sealer = new JweSealer(jwtProperties.secret(), "identity-service:oauth2-state-cookie");
        this.clock = clock;
    }

    /**
     * What the caller needs to start a login.
     *
     * @param state         goes into the authorization URL as {@code state}
     * @param nonce         goes into the authorization URL as {@code nonce}
     * @param codeChallenge goes into the authorization URL as {@code code_challenge} (method S256)
     * @param cookieValue   goes into the cookie sent to the browser
     */
    public record PendingLogin(String state, String nonce, String codeChallenge, String cookieValue) {
    }

    /** What the caller gets back when the user returns: the values to check the token and the code with. */
    public record ResumedLogin(String nonce, String codeVerifier) {
    }

    public PendingLogin start(AuthProvider provider) {
        String state = randomToken();
        String nonce = randomToken();
        String codeVerifier = randomToken();

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("provider", provider.name());
        payload.put("state", state);
        payload.put("nonce", nonce);
        payload.put("cv", codeVerifier);
        payload.put("exp", Instant.now(clock).plus(STATE_TTL).getEpochSecond());

        return new PendingLogin(state, nonce, codeChallengeFor(codeVerifier), sealer.seal(payload));
    }

    /**
     * Reads the cookie when the user comes back, and checks it belongs to this very login.
     *
     * @param cookieValue    the cookie the browser sent back
     * @param stateFromQuery the {@code state} parameter Google put on the return URL
     * @throws GeneralException INVALID_OAUTH_STATE when the cookie is missing, altered, expired, made for
     *                          another provider, or its state is not the one that came back
     */
    public ResumedLogin resume(AuthProvider provider, String cookieValue, String stateFromQuery) {
        if (cookieValue == null || cookieValue.isBlank() || stateFromQuery == null || stateFromQuery.isBlank()) {
            throw rejected("cookie or state missing");
        }

        Map<String, Object> payload = sealer.open(cookieValue).orElseThrow(() -> rejected("not valid"));

        // The cookie is encrypted and authenticated (AES-GCM): whoever got this far holds a value this
        // server made. What is left is to check it is still fresh and is the right one for this request.
        long expiresAt = number(payload, "exp");
        if (!Instant.now(clock).isBefore(Instant.ofEpochSecond(expiresAt))) {
            throw rejected("expired");
        }
        if (!provider.name().equals(text(payload, "provider"))) {
            throw rejected("made for another provider");
        }
        if (!sameValue(text(payload, "state"), stateFromQuery)) {
            throw rejected("state does not match");
        }

        return new ResumedLogin(text(payload, "nonce"), text(payload, "cv"));
    }

    /** code_challenge = BASE64URL(SHA-256(code_verifier)), the S256 method of RFC 7636. */
    static String codeChallengeFor(String codeVerifier) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (GeneralSecurityException e) {
            // Every Java platform must provide SHA-256.
            throw new IllegalStateException(e);
        }
    }

    private String randomToken() {
        byte[] bytes = new byte[RANDOM_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String text(Map<String, Object> payload, String name) {
        if (payload.get(name) instanceof String value && !value.isBlank()) {
            return value;
        }
        throw rejected("claim " + name + " missing");
    }

    private long number(Map<String, Object> payload, String name) {
        if (payload.get(name) instanceof Number value) {
            return value.longValue();
        }
        throw rejected("claim " + name + " missing");
    }

    // Compares in constant time, so how long the answer takes does not reveal how much of it was right.
    private static boolean sameValue(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }

    // The reason is for the operators' log only. The cookie and the state are never logged.
    private GeneralException rejected(String reason) {
        log.warn("Login state rejected: {}", reason);
        return new GeneralException(ErrorCode.INVALID_OAUTH_STATE);
    }
}
