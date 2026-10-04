package com.example.identity_service.service.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.JwtProperties;
import com.example.identity_service.model.JwtUser;
import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.model.User;
import com.example.identity_service.repository.UserRepository;
import com.example.identity_service.service.UserService;

// Real JwtServiceImpl; the refresh token store is mocked (its rules are tested in RefreshTokenServiceImplTest).
class AuthenticationServiceImplRefreshTest {

    private static final JwtProperties PROPERTIES = new JwtProperties("refresh-test-secret-".repeat(3), Duration.ofMinutes(15));

    private final JwtServiceImpl jwtService = new JwtServiceImpl(PROPERTIES);
    private final RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);

    private final AuthenticationServiceImpl service = new AuthenticationServiceImpl(
            mock(UserService.class), mock(UserRepository.class), PasswordEncoderFactories.createDelegatingPasswordEncoder(),
            jwtService, PROPERTIES, refreshTokenService);

    @Test
    void refreshGivesANewAccessTokenForTheOwnerAndTheNewRefreshToken() {
        UUID userId = UUID.randomUUID();
        User user = User.builder().id(userId).email("phong@example.com").passwordHash("{x}hash")
                .roles(Set.of(new Role((short) 1, RoleEnum.USER))).build();
        when(refreshTokenService.rotate("old-refresh")).thenReturn(new RotatedRefreshToken(user, "new-refresh"));

        AuthTokens response = service.refresh("old-refresh");

        assertThat(response.refreshToken()).isEqualTo("new-refresh");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900);
        JwtUser tokenUser = jwtService.getUserFromToken(response.accessToken());
        assertThat(tokenUser.id()).isEqualTo(userId);
        assertThat(tokenUser.authorities()).containsExactly("ROLE_USER");
    }

    // Roles come from the database at every refresh, which is how a change of roles reaches the user.
    @Test
    void theNewAccessTokenCarriesTheRolesTheUserHasNow() {
        User promoted = User.builder().id(UUID.randomUUID()).email("phong@example.com").passwordHash("{x}hash")
                .roles(Set.of(new Role((short) 2, RoleEnum.ADMIN))).build();
        when(refreshTokenService.rotate("old-refresh")).thenReturn(new RotatedRefreshToken(promoted, "new-refresh"));

        AuthTokens response = service.refresh("old-refresh");

        assertThat(jwtService.getUserFromToken(response.accessToken()).authorities()).containsExactly("ROLE_ADMIN");
    }

    @Test
    void aRejectedRefreshTokenIsPassedOnUnchanged() {
        when(refreshTokenService.rotate("bad")).thenThrow(new GeneralException(ErrorCode.INVALID_REFRESH_TOKEN));

        assertThatThrownBy(() -> service.refresh("bad"))
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN));
    }

    @Test
    void logoutRevokesTheRefreshToken() {
        service.logout("the-token");

        verify(refreshTokenService).revoke("the-token");
    }
}
