package com.example.identity_service.service.authentication;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.RefreshToken;
import com.example.identity_service.model.RefreshTokenProperties;
import com.example.identity_service.model.User;
import com.example.identity_service.repository.RefreshTokenRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
@Slf4j
public class RefreshTokenServiceImpl implements RefreshTokenService {
    // 256 bits from a cryptographically secure generator: impossible to guess, so a fast hash is enough
    // to store it (unlike passwords, which are guessable and need a slow one).
    private static final int TOKEN_BYTES = 32;

    private final SecureRandom secureRandom = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenProperties properties;

    public RefreshTokenServiceImpl(RefreshTokenRepository refreshTokenRepository, RefreshTokenProperties properties) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.properties = properties;
    }

    @Override
    @Transactional
    public String create(User user) {
        return store(user, UUID.randomUUID());
    }

    // noRollbackFor is essential. When a reused token is detected the family is revoked and then an
    // exception is thrown. A normal @Transactional would roll the revocation back together with
    // everything else, and the stolen token's family would stay valid.
    @Override
    @Transactional(noRollbackFor = GeneralException.class)
    public RotatedRefreshToken rotate(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw rejected("empty token");
        }
        RefreshToken current = refreshTokenRepository.findByTokenHash(hash(refreshToken))
                .orElseThrow(() -> rejected("unknown token"));
        Instant now = Instant.now();

        // Retire the token first and atomically: of two requests sending the same token at once, the
        // database lets exactly one through (it updates a row only if revoked_at is still empty).
        if (refreshTokenRepository.revoke(current.getId(), now) == 0) {
            // The token was already used or logged out, yet someone presents it again. Either an attacker
            // holds a copy or the client replayed an old one: end the whole login to be safe.
            refreshTokenRepository.revokeFamily(current.getFamilyId(), now);
            throw rejected("token used twice, family revoked");
        }

        if (!current.getExpiresAt().isAfter(now)) {
            throw rejected("expired");
        }

        User user = current.getUser();
        if (!user.isEnabled()) {
            refreshTokenRepository.revokeFamily(current.getFamilyId(), now);
            throw rejected("account disabled, family revoked");
        }

        return new RotatedRefreshToken(user, store(user, current.getFamilyId()));
    }

    @Override
    @Transactional
    public void revoke(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return;
        }
        // Unknown tokens are ignored: logging out twice, or with a made-up token, is not an error and
        // the answer must not tell which tokens exist.
        refreshTokenRepository.findByTokenHash(hash(refreshToken))
                .ifPresent(token -> refreshTokenRepository.revokeFamily(token.getFamilyId(), Instant.now()));
    }

    private String store(User user, UUID familyId) {
        byte[] random = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(random);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(random);

        refreshTokenRepository.save(RefreshToken.builder()
                .user(user)
                .familyId(familyId)
                .tokenHash(hash(token))
                .expiresAt(Instant.now().plus(properties.ttl()))
                .build());

        return token;
    }

    static String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // Every Java platform must provide SHA-256.
            throw new IllegalStateException(e);
        }
    }

    // The reason is for the operators' log only. The client always gets the same answer, so it cannot
    // tell an unknown token from an expired or a reused one. The token is never logged.
    private GeneralException rejected(String reason) {
        log.warn("Refresh token rejected: {}", reason);
        return new GeneralException(ErrorCode.INVALID_REFRESH_TOKEN);
    }
}
