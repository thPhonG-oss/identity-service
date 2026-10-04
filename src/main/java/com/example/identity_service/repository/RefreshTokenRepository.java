package com.example.identity_service.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.example.identity_service.model.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    // The user and their roles are needed to issue the next access token after the transaction is over,
    // and open-in-view is off, so they are loaded here.
    @EntityGraph(attributePaths = { "user", "user.roles" })
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Marks one token as used, but only if nobody has yet. Returns 1 for the caller that won and 0 for
     * everyone else. Being a single conditional UPDATE, it is safe when the same token is sent twice at
     * the same time: the database lets exactly one of them through.
     */
    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.revokedAt = :now where t.id = :id and t.revokedAt is null")
    int revoke(@Param("id") UUID id, @Param("now") Instant now);

    /** Revokes every token of a login that is still valid. Returns how many were revoked. */
    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.revokedAt = :now where t.familyId = :familyId and t.revokedAt is null")
    int revokeFamily(@Param("familyId") UUID familyId, @Param("now") Instant now);
}
