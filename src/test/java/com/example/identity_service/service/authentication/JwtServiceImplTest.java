package com.example.identity_service.service.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.text.ParseException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.CustomUserDetails;
import com.example.identity_service.model.JwtProperties;
import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.model.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

// Plain unit test, no Spring. The token is parsed and verified with Nimbus, like a consumer would do.
class JwtServiceImplTest {

    private static final String SECRET = "unit-test-secret-at-least-32-bytes-long!!";
    private static final Duration TTL = Duration.ofMinutes(15);

    private final JwtServiceImpl jwtService = new JwtServiceImpl(new JwtProperties(SECRET, TTL));

    private static final Role USER_ROLE = new Role((short) 1, RoleEnum.USER);
    private static final Role ADMIN_ROLE = new Role((short) 2, RoleEnum.ADMIN);

    @Test
    void producesASignedHs256TokenWithThreeParts() throws Exception {
        String token = jwtService.generateAccessToken(authenticationOf(newUser(UUID.randomUUID(), USER_ROLE)));

        assertThat(token.split("\\.")).hasSize(3);
        assertThat(SignedJWT.parse(token).getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
    }

    @Test
    void signatureVerifiesWithTheSecretAndNotWithAnotherOne() throws Exception {
        SignedJWT jwt = SignedJWT.parse(jwtService.generateAccessToken(authenticationOf(newUser(UUID.randomUUID(), USER_ROLE))));

        assertThat(jwt.verify(new MACVerifier(SECRET))).isTrue();
        assertThat(jwt.verify(new MACVerifier("another-secret-also-at-least-32-bytes!!!"))).isFalse();
    }

    @Test
    void claimsIdentifyTheUserAndTheIssuer() throws Exception {
        UUID userId = UUID.randomUUID();

        JWTClaimsSet claims = claimsOf(jwtService.generateAccessToken(authenticationOf(newUser(userId, USER_ROLE))));

        assertThat(claims.getIssuer()).isEqualTo(JwtServiceImpl.ISSUER);
        assertThat(claims.getSubject()).isEqualTo(userId.toString());
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(claims.getStringClaim("scope")).isEqualTo("ROLE_USER");
    }

    @Test
    void expirationIsIssueTimePlusTheConfiguredTtl() throws Exception {
        JWTClaimsSet claims = claimsOf(jwtService.generateAccessToken(authenticationOf(newUser(UUID.randomUUID(), USER_ROLE))));

        long lifetimeMillis = claims.getExpirationTime().getTime() - claims.getIssueTime().getTime();

        assertThat(lifetimeMillis).isEqualTo(TTL.toMillis());
    }

    @Test
    void scopeListsEveryRoleSeparatedBySpaces() throws Exception {
        JWTClaimsSet claims = claimsOf(jwtService.generateAccessToken(
                authenticationOf(newUser(UUID.randomUUID(), USER_ROLE, ADMIN_ROLE))));

        assertThat(Arrays.asList(claims.getStringClaim("scope").split(" ")))
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void everyTokenGetsItsOwnId() throws Exception {
        Authentication authentication = authenticationOf(newUser(UUID.randomUUID(), USER_ROLE));

        String first = claimsOf(jwtService.generateAccessToken(authentication)).getJWTID();
        String second = claimsOf(jwtService.generateAccessToken(authentication)).getJWTID();

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void secretShorterThan256BitsFailsWithoutLeakingDetails() {
        JwtServiceImpl weakService = new JwtServiceImpl(new JwtProperties("too-short", TTL));

        assertThatThrownBy(() -> weakService.generateAccessToken(authenticationOf(newUser(UUID.randomUUID(), USER_ROLE))))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR));
    }

    @Test
    void principalOfAnotherTypeIsRejected() {
        Authentication notOurs = UsernamePasswordAuthenticationToken.authenticated("just-a-string", null, Set.of());

        assertThatThrownBy(() -> jwtService.generateAccessToken(notOurs)).isInstanceOf(IllegalArgumentException.class);
    }

    private static JWTClaimsSet claimsOf(String token) throws ParseException, JOSEException {
        return SignedJWT.parse(token).getJWTClaimsSet();
    }

    private static Authentication authenticationOf(User user) {
        CustomUserDetails details = new CustomUserDetails(user);
        return UsernamePasswordAuthenticationToken.authenticated(details, null, details.getAuthorities());
    }

    private static User newUser(UUID id, Role... roles) {
        return User.builder()
                .id(id)
                .email("phong@example.com")
                .passwordHash("{test}not-a-real-hash")
                .roles(Set.of(roles))
                .build();
    }
}
