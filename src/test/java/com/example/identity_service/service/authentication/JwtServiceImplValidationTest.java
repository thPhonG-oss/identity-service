package com.example.identity_service.service.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.CustomUserDetails;
import com.example.identity_service.model.JwtProperties;
import com.example.identity_service.model.JwtUser;
import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.model.User;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

// Long enough (70 bytes) to sign with HS512 as well, to test that only HS256 is accepted.
class JwtServiceImplValidationTest {

    private static final String SECRET = "s3cret-".repeat(10);
    private static final Duration TTL = Duration.ofMinutes(15);

    private final JwtServiceImpl jwtService = new JwtServiceImpl(new JwtProperties(SECRET, TTL));

    // ---- accepted --------------------------------------------------------------------------------

    @Test
    void aTokenWeIssuedIsAccepted() {
        assertThat(jwtService.validateToken(issuedToken(UUID.randomUUID()))).isTrue();
    }

    @Test
    void theUserIsReadFromTheClaims() {
        UUID userId = UUID.randomUUID();

        JwtUser user = jwtService.getUserFromToken(issuedToken(userId));

        assertThat(user.id()).isEqualTo(userId);
        assertThat(user.authorities()).containsExactly("ROLE_USER");
    }

    @Test
    void aTokenWithoutScopeGivesNoAuthorities() throws Exception {
        String token = signed(claims()
                .issuer(JwtServiceImpl.ISSUER)
                .subject(UUID.randomUUID().toString())
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build());

        assertThat(jwtService.getUserFromToken(token).authorities()).isEmpty();
    }

    // ---- expired / not yet valid -----------------------------------------------------------------

    @Test
    void anExpiredTokenIsRejectedAsExpired() {
        JwtServiceImpl expiredIssuer = new JwtServiceImpl(new JwtProperties(SECRET, Duration.ofSeconds(-10)));
        String expired = expiredIssuer.generateAccessToken(authenticationOf(UUID.randomUUID()));

        assertThat(jwtService.validateToken(expired)).isFalse();
        assertRejected(() -> jwtService.getUserFromToken(expired), ErrorCode.TOKEN_EXPIRED);
    }

    @Test
    void aTokenNotValidYetIsRejected() throws Exception {
        String token = signed(validClaims().notBeforeTime(Date.from(Instant.now().plusSeconds(300))).build());

        assertRejected(() -> jwtService.getUserFromToken(token), ErrorCode.INVALID_TOKEN);
    }

    @Test
    void aTokenWithoutExpirationIsRejectedBecauseItWouldNeverExpire() throws Exception {
        String token = signed(claims().issuer(JwtServiceImpl.ISSUER).subject(UUID.randomUUID().toString()).build());

        assertRejected(() -> jwtService.getUserFromToken(token), ErrorCode.INVALID_TOKEN);
    }

    // ---- forged or tampered ----------------------------------------------------------------------

    @Test
    void aTokenSignedWithAnotherSecretIsRejected() {
        JwtServiceImpl stranger = new JwtServiceImpl(new JwtProperties("another-secret-".repeat(5), TTL));
        String forged = stranger.generateAccessToken(authenticationOf(UUID.randomUUID()));

        assertRejected(() -> jwtService.getUserFromToken(forged), ErrorCode.INVALID_TOKEN);
    }

    @Test
    void changingThePayloadBreaksTheSignature() {
        String[] parts = issuedToken(UUID.randomUUID()).split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8)
                .replace("ROLE_USER", "ROLE_ADMIN");
        String tampered = parts[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];

        assertThat(payload).contains("ROLE_ADMIN");
        assertRejected(() -> jwtService.getUserFromToken(tampered), ErrorCode.INVALID_TOKEN);
    }

    @Test
    void anotherSigningAlgorithmIsRejectedEvenWithTheRightSecret() throws Exception {
        SignedJWT hs512 = new SignedJWT(new JWSHeader(JWSAlgorithm.HS512), validClaims().build());
        hs512.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));

        assertRejected(() -> jwtService.getUserFromToken(hs512.serialize()), ErrorCode.INVALID_TOKEN);
    }

    @Test
    void theNoneAlgorithmIsRejected() {
        String header = base64("{\"alg\":\"none\"}");
        String payload = base64("{\"iss\":\"" + JwtServiceImpl.ISSUER + "\",\"sub\":\"" + UUID.randomUUID()
                + "\",\"exp\":" + Instant.now().plusSeconds(600).getEpochSecond() + "}");

        assertRejected(() -> jwtService.getUserFromToken(header + "." + payload + "."), ErrorCode.INVALID_TOKEN);
    }

    @Test
    void aTokenFromAnotherIssuerIsRejected() throws Exception {
        String token = signed(validClaims().issuer("someone-else").build());

        assertRejected(() -> jwtService.getUserFromToken(token), ErrorCode.INVALID_TOKEN);
    }

    // ---- not a token we issued -------------------------------------------------------------------

    @Test
    void aSubjectThatIsNotAUserIdIsRejected() throws Exception {
        String token = signed(validClaims().subject("admin").build());

        assertRejected(() -> jwtService.getUserFromToken(token), ErrorCode.INVALID_TOKEN);
    }

    @Test
    void aTokenWithoutSubjectIsRejected() throws Exception {
        String token = signed(claims().issuer(JwtServiceImpl.ISSUER)
                .expirationTime(Date.from(Instant.now().plusSeconds(600))).build());

        assertRejected(() -> jwtService.getUserFromToken(token), ErrorCode.INVALID_TOKEN);
    }

    @Test
    void garbageNeverThrowsFromValidateToken() {
        for (String garbage : new String[] { null, "", "   ", "abc", "a.b.c", "a.b", "....", "eyJhbGciOiJIUzI1NiJ9.e30." }) {
            assertThat(jwtService.validateToken(garbage)).as("token: %s", garbage).isFalse();
            assertRejected(() -> jwtService.getUserFromToken(garbage), ErrorCode.INVALID_TOKEN);
        }
    }

    // ---- our own misconfiguration ----------------------------------------------------------------

    @Test
    void aTooShortSecretIsAServerErrorNotAnInvalidToken() {
        String token = issuedToken(UUID.randomUUID());
        JwtServiceImpl misconfigured = new JwtServiceImpl(new JwtProperties("too-short", TTL));

        assertRejected(() -> misconfigured.validateToken(token), ErrorCode.INTERNAL_ERROR);
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private static void assertRejected(Runnable action, ErrorCode expected) {
        assertThatThrownBy(action::run)
                .isInstanceOfSatisfying(GeneralException.class, ex -> assertThat(ex.getErrorCode()).isEqualTo(expected));
    }

    private String issuedToken(UUID userId) {
        return jwtService.generateAccessToken(authenticationOf(userId));
    }

    private static Authentication authenticationOf(UUID userId) {
        User user = User.builder().id(userId).email("phong@example.com").passwordHash("{test}hash")
                .roles(Set.of(new Role((short) 1, RoleEnum.USER))).build();
        CustomUserDetails details = new CustomUserDetails(user);
        return UsernamePasswordAuthenticationToken.authenticated(details, null, details.getAuthorities());
    }

    private static JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder();
    }

    // Claims that pass every check; individual tests break one of them.
    private static JWTClaimsSet.Builder validClaims() {
        return claims()
                .issuer(JwtServiceImpl.ISSUER)
                .subject(UUID.randomUUID().toString())
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .claim("scope", "ROLE_USER");
    }

    // Signs with the real secret and HS256, so only the claims decide whether the token is accepted.
    private static String signed(JWTClaimsSet claimsSet) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        jwt.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    private static String base64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
