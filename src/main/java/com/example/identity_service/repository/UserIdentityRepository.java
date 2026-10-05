package com.example.identity_service.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.UserIdentity;

public interface UserIdentityRepository extends JpaRepository<UserIdentity, UUID> {

    // A sign-in with a provider needs the user and their roles to issue tokens after the transaction is
    // over, and open-in-view is off, so they are loaded here.
    @EntityGraph(attributePaths = { "user", "user.roles" })
    Optional<UserIdentity> findByProviderAndProviderUserId(AuthProvider provider, String providerUserId);
}
