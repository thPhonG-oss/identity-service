package com.example.identity_service.service.authentication;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.CustomUserDetails;
import com.example.identity_service.model.JwtProperties;
import com.example.identity_service.model.JwtUser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
public class JwtServiceImpl implements JwtService{
    // The same value must be checked in the "iss" claim when a token is validated.
    public static final String ISSUER = "identity-service";

    private final JwtProperties jwtProperties;

    public JwtServiceImpl(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @Override
    public String generateAccessToken(Authentication authentication) {
        if (!(authentication.getPrincipal() instanceof CustomUserDetails currentUser)) {
            throw new IllegalArgumentException("Principal must be a CustomUserDetails");
        }

        // Space-delimited, the format OAuth2 uses for the "scope" claim, e.g. "ROLE_USER ROLE_ADMIN".
        // Taken from the user, not from the Authentication: since Spring Security 7 a password login adds
        // an extra FACTOR_PASSWORD authority there, which says how the user logged in, not what they may do.
        String scope = currentUser.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        // One "now" for both claims, so exp - iat is exactly the configured TTL.
        Instant now = Instant.now();

        // "sub" is the user id: unlike the email it never changes and is safe to compare with the
        // id in a URL (e.g. to check that a user only reads their own data).
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(currentUser.getUser().getId().toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(jwtProperties.accessTokenTtl())))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", scope)
                .build();

        // Sign and serialize must happen in this order: serialize() throws on an unsigned JWT.
        try {
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSet);
            signedJWT.sign(new MACSigner(jwtProperties.secret().getBytes(StandardCharsets.UTF_8)));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            // Usually a secret shorter than 256 bits. Do not leak the reason to the client.
            log.error("Could not sign the access token", e);
            throw new GeneralException(ErrorCode.INTERNAL_ERROR);
        }
    }

    @Override
    public boolean validateToken(String token) {
        try {
            parseAndVerify(token);
            return true;
        } catch (GeneralException e) {
            // A rejected token is an expected outcome. A server problem (wrong secret length) must
            // still surface, so only the two token errors are turned into "false".
            if (e.getErrorCode() == ErrorCode.INVALID_TOKEN || e.getErrorCode() == ErrorCode.TOKEN_EXPIRED) {
                return false;
            }
            throw e;
        }
    }

    @Override
    public JwtUser getUserFromToken(String token) {
        JWTClaimsSet claims = parseAndVerify(token);

        String subject = claims.getSubject();
        if (subject == null) {
            throw rejected(ErrorCode.INVALID_TOKEN, "no sub claim");
        }

        try {
            UUID userId = UUID.fromString(subject);
            String scope = claims.getStringClaim("scope");
            List<String> authorities = (scope == null || scope.isBlank())
                    ? List.of()
                    : List.of(scope.trim().split("\\s+"));
            return new JwtUser(userId, authorities);
        } catch (IllegalArgumentException | ParseException e) {
            // sub is not a UUID, or scope is not a string: not a token this service issued.
            throw rejected(ErrorCode.INVALID_TOKEN, "malformed sub or scope claim");
        }
    }

    /**
     * Every check a token must pass, in an order that matters: nothing inside the token is trusted
     * until its signature has been verified, so the claims (and the expiry) are only looked at last.
     */
    private JWTClaimsSet parseAndVerify(String token) {
        if (token == null || token.isBlank()) {
            throw rejected(ErrorCode.INVALID_TOKEN, "empty token");
        }

        // 1. Parse: three Base64URL parts with a JSON header and payload.
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw rejected(ErrorCode.INVALID_TOKEN, "not a signed JWT");
        }

        // 2. Algorithm: accept only the one we sign with. Never let the token choose how it is verified.
        if (!JWSAlgorithm.HS256.equals(signedJWT.getHeader().getAlgorithm())) {
            throw rejected(ErrorCode.INVALID_TOKEN, "unexpected algorithm " + signedJWT.getHeader().getAlgorithm());
        }

        // 3. Signature. verify() returns false for a bad signature, it does not throw.
        try {
            if (!signedJWT.verify(new MACVerifier(jwtProperties.secret().getBytes(StandardCharsets.UTF_8)))) {
                throw rejected(ErrorCode.INVALID_TOKEN, "signature does not match");
            }
        } catch (JOSEException e) {
            // Our own configuration is wrong (secret too short). Not the caller's fault.
            log.error("Could not verify the access token", e);
            throw new GeneralException(ErrorCode.INTERNAL_ERROR);
        }

        // 4. Claims, now that they can be trusted.
        JWTClaimsSet claims;
        try {
            claims = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw rejected(ErrorCode.INVALID_TOKEN, "claims are not valid JSON");
        }

        if (!ISSUER.equals(claims.getIssuer())) {
            throw rejected(ErrorCode.INVALID_TOKEN, "wrong issuer");
        }

        // A token without exp would never expire, so exp is required.
        Date expiration = claims.getExpirationTime();
        if (expiration == null) {
            throw rejected(ErrorCode.INVALID_TOKEN, "no exp claim");
        }

        Instant now = Instant.now();
        if (!expiration.toInstant().isAfter(now)) {
            throw rejected(ErrorCode.TOKEN_EXPIRED, "expired at " + expiration.toInstant());
        }

        Date notBefore = claims.getNotBeforeTime();
        if (notBefore != null && notBefore.toInstant().isAfter(now)) {
            throw rejected(ErrorCode.INVALID_TOKEN, "not valid yet");
        }

        return claims;
    }

    // The reason goes to the debug log only: the client just learns "invalid" or "expired".
    // The token itself is never logged, it is a credential.
    private GeneralException rejected(ErrorCode errorCode, String reason) {
        log.debug("JWT rejected: {}", reason);
        return new GeneralException(errorCode);
    }
}
