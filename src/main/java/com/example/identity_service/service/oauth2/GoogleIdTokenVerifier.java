package com.example.identity_service.service.oauth2;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.AuthProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Set;

/**
 * Checks the ID token Google returns when the authorization code is exchanged, and says who the user is.
 *
 * The token is a JWT signed by Google with its private key (RS256). Unlike the tokens this application
 * issues, nobody here holds a secret: the public keys are downloaded from Google (a JWKS) and the token
 * names the one to use in its "kid" header.
 *
 * Every check answers a different attack, see {@link #verify}.
 */
@Slf4j
public class GoogleIdTokenVerifier {

    // Google documents both spellings of its issuer.
    private static final Set<String> ISSUERS = Set.of("https://accounts.google.com", "accounts.google.com");

    private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();

    /**
     * @param jwkSource where Google's public keys come from. Passed in, instead of downloaded in here, so
     *                  a test can supply its own keys and no network is needed.
     * @param clientId  the client id of this application at Google. A token issued for another
     *                  application carries a different id, and is refused.
     */
    public GoogleIdTokenVerifier(JWKSource<SecurityContext> jwkSource, String clientId) {
        // Only RS256 is accepted. The token does not get to choose how it is verified: a token that
        // claims HS256, or no signature at all, finds no key and is rejected.
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource));

        // Checked for us: the audience, that the token has not expired (60 seconds of clock difference
        // are tolerated) and is not used before its "nbf", and that these claims exist at all.
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                Set.of(clientId), null, Set.of("sub", "iss", "aud", "exp", "iat"), null));
    }

    /**
     * Verifies the token and returns the identity it carries.
     *
     * <ul>
     *   <li>signature, with the key named by "kid": the token really comes from Google and was not changed;</li>
     *   <li>audience (aud) is this application: a token Google issued to another application, handed to us by
     *       a malicious one, is refused;</li>
     *   <li>expiry (exp): an old, captured token cannot be used again;</li>
     *   <li>issuer (iss) is Google;</li>
     *   <li>nonce is the one generated for this very login: a token captured from another login cannot be
     *       replayed here;</li>
     *   <li>the email exists and is verified: an unverified address proves nothing about its owner.</li>
     * </ul>
     *
     * @param idToken       the compact JWT from the token endpoint
     * @param expectedNonce the nonce that was sent in the authorization request
     * @throws GeneralException INVALID_ID_TOKEN when the token fails a check, INTERNAL_ERROR when Google's
     *                          keys could not be fetched (not the user's fault)
     */
    public ExternalIdentity verify(String idToken, String expectedNonce) {
        if (idToken == null || idToken.isBlank()) {
            throw rejected("empty token");
        }
        if (expectedNonce == null || expectedNonce.isBlank()) {
            // Nothing to compare with would silently turn the nonce check off.
            throw new IllegalArgumentException("expectedNonce is required");
        }

        JWTClaimsSet claims;
        try {
            claims = processor.process(idToken, null);
        } catch (ParseException | BadJOSEException e) {
            // Not a JWT, wrong algorithm, no matching key, bad signature, wrong audience, expired, ...
            throw rejected(e.getMessage());
        } catch (JOSEException e) {
            // e.g. Google's keys could not be downloaded. The user did nothing wrong.
            log.error("Could not verify the Google ID token", e);
            throw new GeneralException(ErrorCode.INTERNAL_ERROR);
        }

        try {
            if (!ISSUERS.contains(claims.getIssuer())) {
                throw rejected("wrong issuer");
            }
            if (!sameValue(expectedNonce, claims.getStringClaim("nonce"))) {
                throw rejected("nonce does not match");
            }
            String subject = claims.getSubject();
            if (subject == null || subject.isBlank()) {
                throw rejected("no sub claim");
            }
            String email = claims.getStringClaim("email");
            if (email == null || email.isBlank()) {
                throw rejected("no email claim");
            }
            if (!isTrue(claims.getClaim("email_verified"))) {
                throw rejected("email is not verified");
            }
            return new ExternalIdentity(AuthProvider.GOOGLE, subject, email);
        } catch (ParseException e) {
            // a claim that should be text is something else
            throw rejected("malformed claim");
        }
    }

    // Google has sent email_verified both as a boolean and as the text "true".
    private static boolean isTrue(Object value) {
        return Boolean.TRUE.equals(value) || (value instanceof String text && Boolean.parseBoolean(text));
    }

    // Compares in constant time, so how long the answer takes does not reveal how much of it was right.
    private static boolean sameValue(String expected, String actual) {
        return actual != null && MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }

    // The reason is for the operators' log only. The token itself is never logged: it carries personal data.
    private GeneralException rejected(String reason) {
        log.warn("Google ID token rejected: {}", reason);
        return new GeneralException(ErrorCode.INVALID_ID_TOKEN);
    }
}
