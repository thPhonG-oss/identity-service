package com.example.identity_service.service.oauth2;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

/**
 * Seals a few values into an encrypted string that can travel through the browser (in a cookie), and opens
 * it again. Encrypted and authenticated (JWE, AES-256-GCM): nobody can read the values, and nobody can
 * change them or make a sealed string of their own without being noticed.
 *
 * Each purpose gets a key of its own, made from the application's secret and a label for that purpose. A
 * string sealed for one purpose cannot be opened for another, so the cookie that remembers a login in
 * progress and the one that remembers an account waiting to be linked cannot stand in for each other.
 */
public class JweSealer {

    private final byte[] key;

    /**
     * @param secret the application's secret; only used to derive the key
     * @param label  names the purpose, e.g. "identity-service:oauth2-state-cookie". Two purposes must never
     *               share a label.
     */
    public JweSealer(String secret, String label) {
        this.key = deriveKey(secret, label);
    }

    public String seal(Map<String, Object> values) {
        try {
            // "dir": the key is used directly, no key wrapping. A256GCM: encryption plus a tamper check.
            JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM), new Payload(values));
            jwe.encrypt(new DirectEncrypter(key));
            return jwe.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not seal the values", e);
        }
    }

    /**
     * @return the values, or empty when the string is not something this sealer made: wrong key or purpose,
     *         altered, not encrypted at all, or malformed in any way
     */
    public Optional<Map<String, Object>> open(String sealed) {
        try {
            JWEObject jwe = JWEObject.parse(sealed);
            jwe.decrypt(new DirectDecrypter(key));
            return Optional.ofNullable(jwe.getPayload().toJSONObject());
        } catch (ParseException | JOSEException | RuntimeException e) {
            // The string comes from the browser, so anything can be in it. Not every malformed value makes
            // Nimbus throw ParseException: a header without "enc" makes it throw NullPointerException.
            // Whatever the way it is broken, the answer is the same.
            return Optional.empty();
        }
    }

    // HMAC used as a key derivation: the result is 32 bytes, exactly what AES-256 needs, and is different for
    // every label. Without this, one secret would protect everything, and a flaw or a leak in one place
    // would reach all the others.
    private static byte[] deriveKey(String secret, String label) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return mac.doFinal(label.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
