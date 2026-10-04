package com.example.identity_service.service.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.identity_service.controller.dto.LoginRequest;
import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.JwtProperties;
import com.example.identity_service.model.JwtUser;
import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.model.User;
import com.example.identity_service.repository.UserRepository;
import com.example.identity_service.service.UserService;
import tools.jackson.databind.json.JsonMapper;

// Real password hashing and a real JwtServiceImpl. Only the place users are loaded from is mocked.
class AuthenticationServiceImplLoginTest {

    private static final String PASSWORD = "S3cure-pass!";
    private static final String EMAIL = "phong@example.com";
    private static final JwtProperties PROPERTIES = new JwtProperties("login-test-secret-".repeat(3), Duration.ofMinutes(15));

    // A spy, to see that the password is checked even when there is no user.
    private final PasswordEncoder encoder = spy(PasswordEncoderFactories.createDelegatingPasswordEncoder());
    private final UserRepository userRepository = mock(UserRepository.class);
    private final JwtServiceImpl jwtService = new JwtServiceImpl(PROPERTIES);
    private final UUID userId = UUID.randomUUID();

    private final RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);

    private final AuthenticationServiceImpl service = new AuthenticationServiceImpl(
            mock(UserService.class), userRepository, encoder, jwtService, PROPERTIES, refreshTokenService);

    @Test
    void rightCredentialsGiveAnAccessTokenForThatUser() {
        givenRegisteredUser(true);
        when(refreshTokenService.create(any())).thenReturn("refresh-token-1");

        AuthTokens response = service.login(loginRequest(EMAIL, PASSWORD));

        assertThat(response.refreshToken()).isEqualTo("refresh-token-1");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900);
        assertThat(jwtService.validateToken(response.accessToken())).isTrue();
        JwtUser tokenUser = jwtService.getUserFromToken(response.accessToken());
        assertThat(tokenUser.id()).isEqualTo(userId);
        assertThat(tokenUser.authorities()).containsExactly("ROLE_USER");
    }

    @Test
    void wrongPasswordIsInvalidCredentials() {
        givenRegisteredUser(true);

        assertInvalidCredentials(loginRequest(EMAIL, "wrong-password"));
    }

    @Test
    void noRefreshTokenIsIssuedWhenTheLoginFails() {
        givenRegisteredUser(true);

        assertInvalidCredentials(loginRequest(EMAIL, "wrong-password"));

        verify(refreshTokenService, never()).create(any());
    }

    @Test
    void unknownEmailIsInvalidCredentialsToo() {
        when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        assertInvalidCredentials(loginRequest("nobody@example.com", PASSWORD));
    }

    @Test
    void aDisabledAccountIsInvalidCredentialsEvenWithTheRightPassword() {
        givenRegisteredUser(false);

        assertInvalidCredentials(loginRequest(EMAIL, PASSWORD));
    }

    // The point of the dummy hash: an unknown email must cost as much work as a known one, otherwise the
    // response time reveals which emails are registered.
    @Test
    void thePasswordIsCheckedEvenWhenTheEmailIsUnknown() {
        when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());
        clearInvocations(encoder); // forget the encode() done in the constructor

        assertInvalidCredentials(loginRequest("nobody@example.com", PASSWORD));

        verify(encoder).matches(eq(PASSWORD), anyString());
    }

    @Test
    void thePasswordIsCheckedBeforeTheAccountStateSoADisabledAccountIsNotRevealed() {
        givenRegisteredUser(false);
        clearInvocations(encoder);

        assertInvalidCredentials(loginRequest(EMAIL, "wrong-password"));

        verify(encoder).matches(eq("wrong-password"), anyString());
    }

    @Test
    void aFailureOfOurOwnIsNotReportedAsWrongCredentials() {
        RuntimeException databaseDown = new RuntimeException("db down");
        when(userRepository.findByEmail(EMAIL)).thenThrow(databaseDown);

        assertThatThrownBy(() -> service.login(loginRequest(EMAIL, PASSWORD))).isSameAs(databaseDown);
    }

    // The user is built first: building it uses the encoder spy, which must not happen inside when(...).
    private void givenRegisteredUser(boolean enabled) {
        User registered = user(enabled);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(registered));
    }

    private void assertInvalidCredentials(LoginRequest request) {
        assertThatThrownBy(() -> service.login(request))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS));
    }

    private User user(boolean enabled) {
        return User.builder()
                .id(userId)
                .email(EMAIL)
                .passwordHash(encoder.encode(PASSWORD))
                .enabled(enabled)
                .roles(Set.of(new Role((short) 1, RoleEnum.USER)))
                .build();
    }

    // LoginRequest has no setters, so it is built the way a real request is: from JSON.
    private static LoginRequest loginRequest(String email, String password) {
        String json = "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
        return JsonMapper.builder().build().readValue(json, LoginRequest.class);
    }
}
