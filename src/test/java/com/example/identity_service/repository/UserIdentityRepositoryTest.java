package com.example.identity_service.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import org.hibernate.Hibernate;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

import com.example.identity_service.model.AuthProvider;
import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.model.User;
import com.example.identity_service.model.UserIdentity;

import jakarta.persistence.EntityManager;

// Against the real Postgres, so the V6 migration is checked too. Each test is rolled back.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
class UserIdentityRepositoryTest {

    @Autowired
    private UserIdentityRepository userIdentityRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private EntityManager entityManager;

    @Test
    void aUserCanExistWithoutAPassword() {
        User googleOnly = userRepository.saveAndFlush(newUser(null));
        entityManager.clear();

        assertThat(userRepository.findById(googleOnly.getId())).get().extracting(User::getPasswordHash).isNull();
    }

    @Test
    void anIdentityIsFoundByProviderAndSubjectWithTheUserAndTheirRolesLoaded() {
        User user = newUser("{x}hash");
        user.getRoles().add(roleRepository.findByName(RoleEnum.USER).orElseThrow());
        userRepository.save(user);
        userIdentityRepository.saveAndFlush(identity(user, AuthProvider.GOOGLE, "google-sub-1"));
        entityManager.clear();

        UserIdentity found = userIdentityRepository
                .findByProviderAndProviderUserId(AuthProvider.GOOGLE, "google-sub-1").orElseThrow();

        assertThat(found.getUser().getId()).isEqualTo(user.getId());
        assertThat(found.getCreatedAt()).isNotNull();
        assertThat(Hibernate.isInitialized(found.getUser().getRoles())).isTrue();
        assertThat(found.getUser().getRoles()).extracting(Role::getName).containsExactly(RoleEnum.USER);
    }

    @Test
    void anUnknownAccountOrAnotherProviderIsNotFound() {
        User user = userRepository.save(newUser(null));
        userIdentityRepository.saveAndFlush(identity(user, AuthProvider.GOOGLE, "google-sub-1"));
        entityManager.clear();

        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, "other")).isEmpty();
        // the same id at another provider is a different account
        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GITHUB, "google-sub-1")).isEmpty();
    }

    @Test
    void oneAccountOfAProviderCannotBelongToTwoUsers() {
        userIdentityRepository.saveAndFlush(identity(userRepository.save(newUser(null)), AuthProvider.GOOGLE, "same-sub"));
        UserIdentity second = identity(userRepository.save(newUser(null)), AuthProvider.GOOGLE, "same-sub");

        assertThatThrownBy(() -> userIdentityRepository.saveAndFlush(second))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void aUserCannotLinkTwoAccountsOfTheSameProvider() {
        User user = userRepository.save(newUser(null));
        userIdentityRepository.saveAndFlush(identity(user, AuthProvider.GOOGLE, "first-sub"));
        UserIdentity another = identity(user, AuthProvider.GOOGLE, "second-sub");

        assertThatThrownBy(() -> userIdentityRepository.saveAndFlush(another))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void aUserCanLinkOneAccountPerProvider() {
        User user = userRepository.save(newUser(null));
        userIdentityRepository.saveAndFlush(identity(user, AuthProvider.GOOGLE, "google-sub"));

        userIdentityRepository.saveAndFlush(identity(user, AuthProvider.GITHUB, "github-id"));

        assertThat(userIdentityRepository.count()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void deletingTheUserDeletesTheirIdentities() {
        User user = userRepository.save(newUser(null));
        userIdentityRepository.saveAndFlush(identity(user, AuthProvider.GOOGLE, "google-sub-1"));
        // Start from a clean persistence context: with the identity still managed there, Hibernate refuses
        // to delete the user it points to. The database removes the identity itself (ON DELETE CASCADE).
        entityManager.clear();

        userRepository.deleteById(user.getId());
        userRepository.flush();
        entityManager.clear();

        assertThat(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.GOOGLE, "google-sub-1")).isEmpty();
    }

    private static User newUser(String passwordHash) {
        return User.builder()
                .email("identity_" + UUID.randomUUID().toString().substring(0, 8) + "@example.com")
                .passwordHash(passwordHash)
                .build();
    }

    private static UserIdentity identity(User user, AuthProvider provider, String subject) {
        return UserIdentity.builder().user(user).provider(provider).providerUserId(subject).email(user.getEmail()).build();
    }
}
