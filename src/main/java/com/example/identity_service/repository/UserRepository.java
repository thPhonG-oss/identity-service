package com.example.identity_service.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.example.identity_service.model.User;

// Queries use lower(...) explicitly, not derived "IgnoreCase" methods: Spring Data would generate
// upper(...), which cannot use the lower(email) unique index from V1.
public interface UserRepository extends JpaRepository<User, UUID> {

    // open-in-view is off, so roles must be loaded here; lazy loading would fail outside a transaction.
    @EntityGraph(attributePaths = "roles")
    @Query("select u from User u where lower(u.email) = lower(:email)")
    Optional<User> findByEmail(@Param("email") String email);

    @Query("select count(u) > 0 from User u where lower(u.email) = lower(:email)")
    boolean existsByEmail(@Param("email") String email);
}
