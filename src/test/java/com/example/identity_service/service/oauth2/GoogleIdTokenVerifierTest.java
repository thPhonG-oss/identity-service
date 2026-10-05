package com.example.identity_service.service.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

// No network and no Google: the "Google" in these tests is a key pair made here, and the verifier gets its
// public half as its JWKS, exactly where it would normally get Google's.
class GoogleIdTokenVerifierTest {

    private static final String CLIENT_ID = "my-app.apps.googleusercontent.com";
    private static final String NONCE = "nonce-of-this-login";
    private static final String KEY_ID = "google-key-1";

    private static RSAKey googleKey;
    private static GoogleIdTokenVerifier verifier;

    @BeforeAll
    static void createGoogle() throws Exception {
        googleKey = new RSAKeyGenerator(2048).keyID(KEY_ID).generate();
        JWKSource<SecurityContext> publicKeys = new ImmutableJWKSet<>(new JWKSet(googleKey.toPublicJWK()));
        verifier = new GoogleIdTokenVerifier(publicKeys, CLIENT_ID);
    }

    // ---- accepted --------------------------------------------------------------------------------

    @Test
    void aValidTokenGivesTheIdentity() throws Exception {
        ExternalIdentity identity = verifier.verify(sign(validClaims().build()), NONCE);

        assertThat(identity.provider()).isEqualTo(AuthProvider.GOOGLE);
        assertThat(identity.subject()).isEqualTo("1234567890");
        assertThat(identity.email()).isEqualTo("user@gmail.com");
    }

    @Test
    void theIssuerWithoutHttpsIsAcceptedToo() throws Exception {
        assertThat(verifier.verify(sign(validClaims().issuer("accounts.google.com").build()), NONCE).subject())
                .isEqualTo("1234567890");
    }

    @Test
    void emailVerifiedSentAsTheTextTrueIsAccepted() throws Exception {
        assertThat(verifier.verify(sign(validClaims().claim("email_verified", "true").build()), NONCE)).isNotNull();
    }

    // ---- the claims ------------------------------------------------------------------------------

    @Test
    void aTokenIssuedForAnotherApplicationIsRejected() throws Exception {
        assertInvalid(sign(validClaims().audience("someone-elses-app.apps.googleusercontent.com").build()), NONCE);
    }

    @Test
    void aTokenFromAnotherIssuerIsRejected() throws Exception {
        assertInvalid(sign(validClaims().issuer("https://evil.example.com").build()), NONCE);
    }

    @Test
    void anExpiredTokenIsRejected() throws Exception {
        // two minutes ago: beyond the 60 seconds of clock difference that are tolerated
        assertInvalid(sign(validClaims().expirationTime(Date.from(Instant.now().minusSeconds(120))).build()), NONCE);
    }

    @Test
    void aTokenWithoutExpirationIsRejected() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://accounts.google.com").audience(CLIENT_ID).subject("1234567890")
                .issueTime(new Date()).claim("email", "user@gmail.com").claim("email_verified", true)
                .claim("nonce", NONCE).build();

        assertInvalid(sign(claims), NONCE);
    }

    @Test
    void aTokenFromAnotherLoginIsRejectedBecauseOfTheNonce() throws Exception {
        assertInvalid(sign(validClaims().claim("nonce", "nonce-of-another-login").build()), NONCE);
    }

    @Test
    void aTokenWithoutANonceIsRejected() throws Exception {
        assertInvalid(sign(validClaims().claim("nonce", null).build()), NONCE);
    }

    @Test
    void aTokenWithoutASubjectIsRejected() throws Exception {
        assertInvalid(sign(validClaims().subject(null).build()), NONCE);
    }

    @Test
    void aTokenWithoutAnEmailIsRejected() throws Exception {
        assertInvalid(sign(validClaims().claim("email", null).build()), NONCE);
    }

    @Test
    void anUnverifiedEmailIsRejected() throws Exception {
        assertInvalid(sign(validClaims().claim("email_verified", false).build()), NONCE);
        assertInvalid(sign(validClaims().claim("email_verified", "false").build()), NONCE);
        assertInvalid(sign(validClaims().claim("email_verified", null).build()), NONCE);
    }

    // ---- the signature and the algorithm ---------------------------------------------------------

    @Test
    void aTokenSignedWithAnotherKeyIsRejectedEvenWithTheRightKeyId() throws Exception {
        RSAKey forger = new RSAKeyGenerator(2048).keyID(KEY_ID).generate();

        assertInvalid(sign(validClaims().build(), forger), NONCE);
    }

    @Test
    void aTokenNamingAnUnknownKeyIsRejected() throws Exception {
        RSAKey stranger = new RSAKeyGenerator(2048).keyID("not-a-google-key").generate();

        assertInvalid(sign(validClaims().build(), stranger), NONCE);
    }

    @Test
    void aChangedPayloadIsRejected() throws Exception {
        String[] parts = sign(validClaims().build()).split("\\.");
        String forgedPayload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                validClaims().subject("someone-elses-id").build().toString().getBytes(StandardCharsets.UTF_8));

        assertInvalid(parts[0] + "." + forgedPayload + "." + parts[2], NONCE);
    }

    // The classic attack: sign with HMAC, using the public key (which everybody knows) as the secret. It
    // works against a verifier that lets the token pick the algorithm. This one only accepts RS256.
    @Test
    void aTokenSignedWithHmacUsingThePublicKeyIsRejected() throws Exception {
        byte[] publicKeyBytes = googleKey.toRSAPublicKey().getEncoded();
        SignedJWT forged = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(KEY_ID).type(JOSEObjectType.JWT).build(),
                validClaims().build());
        forged.sign(new MACSigner(publicKeyBytes));

        assertInvalid(forged.serialize(), NONCE);
    }

    @Test
    void aTokenWithoutASignatureIsRejected() {
        assertInvalid(new PlainJWT(validClaims().build()).serialize(), NONCE);
    }

    @Test
    void garbageIsRejected() {
        for (String garbage : new String[] { null, "", "   ", "abc", "a.b.c", "eyJhbGciOiJSUzI1NiJ9.e30." }) {
            assertInvalid(garbage, NONCE);
        }
    }

    // ---- not the user's fault --------------------------------------------------------------------

    @Test
    void whenGooglesKeysCannotBeFetchedItIsAServerErrorNotAnInvalidToken() throws Exception {
        JWKSource<SecurityContext> googleIsDown = (selector, context) -> {
            throw new KeySourceException("Google is not reachable");
        };
        GoogleIdTokenVerifier offline = new GoogleIdTokenVerifier(googleIsDown, CLIENT_ID);
        String token = sign(validClaims().build());

        assertThatThrownBy(() -> offline.verify(token, NONCE))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR));
    }

    @Test
    void aMissingExpectedNonceIsAProgrammingErrorNotASilentPass() throws Exception {
        String token = sign(validClaims().build());

        assertThatThrownBy(() -> verifier.verify(token, null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> verifier.verify(token, " ")).isInstanceOf(IllegalArgumentException.class);
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private static void assertInvalid(String token, String expectedNonce) {
        assertThatThrownBy(() -> verifier.verify(token, expectedNonce))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_ID_TOKEN));
    }

    // The claims of a good token; each test breaks one of them.
    private static JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
                .issuer("https://accounts.google.com")
                .audience(CLIENT_ID)
                .subject("1234567890")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("email", "user@gmail.com")
                .claim("email_verified", true)
                .claim("nonce", NONCE);
    }

    private static String sign(JWTClaimsSet claims) throws Exception {
        return sign(claims, googleKey);
    }

    private static String sign(JWTClaimsSet claims, RSAKey key) throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).type(JOSEObjectType.JWT).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }
}
