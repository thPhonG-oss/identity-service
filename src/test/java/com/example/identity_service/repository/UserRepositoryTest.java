package com.example.identity_service.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hibernate.Hibernate;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

import com.example.identity_service.model.Role;
import com.example.identity_service.model.User;

import jakarta.persistence.EntityManager;

// Runs against the real Postgres from docker-compose (dev profile); each test is rolled back.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private EntityManager entityManager;

    @Test
    void seededRolesExist() {
        assertThat(roleRepository.findByName("USER")).isPresent();
        assertThat(roleRepository.findByName("ADMIN")).isPresent();
    }

    @Test
    void findByUsernameIsCaseInsensitiveAndLoadsRoles() {
        Role userRole = roleRepository.findByName("USER").orElseThrow();
        userRepository.saveAndFlush(newUser("Phong", "phong@example.com", userRole));
        entityManager.clear();

        User found = userRepository.findByUsername("pHONG").orElseThrow();

        assertThat(found.getId()).isNotNull();
        assertThat(found.getCreatedAt()).isNotNull();
        assertThat(Hibernate.isInitialized(found.getRoles())).isTrue();
        assertThat(found.getRoles()).extracting(Role::getName).containsExactly("USER");
    }

    @Test
    void findByEmailAndExistsAreCaseInsensitive() {
        userRepository.saveAndFlush(newUser("phong", "Phong@Example.com"));
        entityManager.clear();

        assertThat(userRepository.findByEmail("phong@example.com")).isPresent();
        assertThat(userRepository.existsByEmail("PHONG@EXAMPLE.COM")).isTrue();
        assertThat(userRepository.existsByUsername("PHONG")).isTrue();
        assertThat(userRepository.existsByUsername("someone-else")).isFalse();
    }

    @Test
    void duplicateUsernameIgnoringCaseIsRejectedByDatabase() {
        userRepository.saveAndFlush(newUser("phong", "a@example.com"));

        assertThatThrownBy(() -> userRepository.saveAndFlush(newUser("PHONG", "b@example.com")))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private static User newUser(String username, String email, Role... roles) {
        User user = User.builder()
                .username(username)
                .email(email)
                .passwordHash("{test}not-a-real-hash")
                .build();
        user.getRoles().addAll(java.util.List.of(roles));
        return user;
    }
}
