package com.example.identity_service.service.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.RefreshToken;
import com.example.identity_service.model.RefreshTokenProperties;
import com.example.identity_service.model.User;
import com.example.identity_service.repository.RefreshTokenRepository;

// The rules of rotation, with the repository mocked. The real database behaviour is in
// RefreshTokenServiceIntegrationTest.
class RefreshTokenServiceImplTest {

    private static final Duration TTL = Duration.ofDays(7);

    private final RefreshTokenRepository repository = mock(RefreshTokenRepository.class);
    private final RefreshTokenServiceImpl service = new RefreshTokenServiceImpl(repository, new RefreshTokenProperties(TTL));

    private final UUID familyId = UUID.randomUUID();

    // ---- create ----------------------------------------------------------------------------------

    @Test
    void createStoresOnlyTheHashOfTheTokenItReturns() {
        User user = user(true);

        String token = service.create(user);

        RefreshToken stored = savedToken();
        assertThat(stored.getTokenHash()).isEqualTo(RefreshTokenServiceImpl.hash(token));
        assertThat(stored.getTokenHash()).isNotEqualTo(token).hasSize(64);
        assertThat(stored.getUser()).isSameAs(user);
        assertThat(stored.getFamilyId()).isNotNull();
        assertThat(stored.getRevokedAt()).isNull();
        assertThat(stored.getExpiresAt()).isBetween(Instant.now().plus(TTL).minusSeconds(5), Instant.now().plus(TTL).plusSeconds(5));
    }

    @Test
    void tokensAreLongRandomAndDifferentEveryTime() {
        String first = service.create(user(true));
        String second = service.create(user(true));

        assertThat(first).isNotEqualTo(second);
        assertThat(first).hasSize(43).matches("[A-Za-z0-9_-]+"); // 256 bits as Base64URL
    }

    @Test
    void everyLoginStartsItsOwnFamily() {
        service.create(user(true));
        service.create(user(true));

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository, org.mockito.Mockito.times(2)).save(captor.capture());
        assertThat(captor.getAllValues().get(0).getFamilyId()).isNotEqualTo(captor.getAllValues().get(1).getFamilyId());
    }

    // ---- rotate ----------------------------------------------------------------------------------

    @Test
    void rotateRetiresTheOldTokenAndIssuesANewOneInTheSameFamily() {
        User user = user(true);
        RefreshToken current = stored("old-token", user, Instant.now().plusSeconds(600));
        when(repository.revoke(eq(current.getId()), any())).thenReturn(1);

        RotatedRefreshToken rotated = service.rotate("old-token");

        assertThat(rotated.user()).isSameAs(user);
        assertThat(rotated.refreshToken()).isNotEqualTo("old-token");
        RefreshToken next = savedToken();
        assertThat(next.getFamilyId()).isEqualTo(familyId);
        assertThat(next.getTokenHash()).isEqualTo(RefreshTokenServiceImpl.hash(rotated.refreshToken()));
        verify(repository, never()).revokeFamily(any(), any());
    }

    @Test
    void anUnknownTokenIsRejectedAndNothingIsIssued() {
        when(repository.findByTokenHash(any())).thenReturn(Optional.empty());

        assertRejected(() -> service.rotate("made-up"));

        verify(repository, never()).save(any());
        verify(repository, never()).revokeFamily(any(), any());
    }

    @Test
    void aTokenThatWasAlreadyUsedRevokesTheWholeFamily() {
        RefreshToken current = stored("old-token", user(true), Instant.now().plusSeconds(600));
        when(repository.revoke(eq(current.getId()), any())).thenReturn(0); // somebody used it before

        assertRejected(() -> service.rotate("old-token"));

        verify(repository).revokeFamily(eq(familyId), any());
        verify(repository, never()).save(any());
    }

    @Test
    void anExpiredTokenIsRejectedAndNothingIsIssued() {
        RefreshToken current = stored("old-token", user(true), Instant.now().minusSeconds(1));
        when(repository.revoke(eq(current.getId()), any())).thenReturn(1);

        assertRejected(() -> service.rotate("old-token"));

        verify(repository, never()).save(any());
    }

    @Test
    void aDisabledAccountCannotRefreshAndItsFamilyIsRevoked() {
        RefreshToken current = stored("old-token", user(false), Instant.now().plusSeconds(600));
        when(repository.revoke(eq(current.getId()), any())).thenReturn(1);

        assertRejected(() -> service.rotate("old-token"));

        verify(repository).revokeFamily(eq(familyId), any());
        verify(repository, never()).save(any());
    }

    @Test
    void aMissingTokenIsRejectedWithoutTouchingTheDatabase() {
        assertRejected(() -> service.rotate(null));
        assertRejected(() -> service.rotate("  "));

        verify(repository, never()).findByTokenHash(any());
    }

    // ---- revoke (logout) -------------------------------------------------------------------------

    @Test
    void logoutRevokesTheWholeFamily() {
        stored("the-token", user(true), Instant.now().plusSeconds(600));

        service.revoke("the-token");

        verify(repository).revokeFamily(eq(familyId), any());
    }

    @Test
    void logoutWithAnUnknownTokenIsQuietlyIgnored() {
        when(repository.findByTokenHash(any())).thenReturn(Optional.empty());

        service.revoke("made-up");

        verify(repository, never()).revokeFamily(any(), any());
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private void assertRejected(Runnable action) {
        assertThatThrownBy(action::run)
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN));
    }

    private RefreshToken savedToken() {
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository).save(captor.capture());
        return captor.getValue();
    }

    // Stores a token under its hash, the way the database would, and makes the repository find it.
    private RefreshToken stored(String rawToken, User user, Instant expiresAt) {
        RefreshToken token = RefreshToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .familyId(familyId)
                .tokenHash(RefreshTokenServiceImpl.hash(rawToken))
                .expiresAt(expiresAt)
                .build();
        when(repository.findByTokenHash(token.getTokenHash())).thenReturn(Optional.of(token));
        return token;
    }

    private static User user(boolean enabled) {
        return User.builder().id(UUID.randomUUID()).email("phong@example.com").passwordHash("{x}hash").enabled(enabled).build();
    }
}
