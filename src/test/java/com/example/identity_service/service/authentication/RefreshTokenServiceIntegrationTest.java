package com.example.identity_service.service.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.RefreshTokenProperties;
import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.model.User;
import com.example.identity_service.repository.RoleRepository;
import com.example.identity_service.repository.UserRepository;

// Against the real Postgres, with every call really committed (a rolled-back test transaction would hide
// what these tests are about). Data uses a random email and is deleted afterwards, so the dev database is
// left as it was; deleting the user also deletes its refresh tokens (ON DELETE CASCADE).
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
@Import(RefreshTokenServiceImpl.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class RefreshTokenServiceIntegrationTest {

    @TestConfiguration
    static class Config {
        @Bean
        RefreshTokenProperties refreshTokenProperties() {
            return new RefreshTokenProperties(Duration.ofDays(7));
        }
    }

    @Autowired
    private RefreshTokenServiceImpl service;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    private User user;

    @BeforeEach
    void createUser() {
        Role userRole = roleRepository.findByName(RoleEnum.USER).orElseThrow();
        User newUser = User.builder()
                .email("refresh_" + UUID.randomUUID().toString().substring(0, 8) + "@example.com")
                .passwordHash("{test}not-a-real-hash")
                .build();
        newUser.getRoles().add(userRole);
        user = userRepository.save(newUser);
    }

    @AfterEach
    void deleteUser() {
        userRepository.deleteById(user.getId());
    }

    @Test
    void rotatingGivesANewTokenAndLoadsTheUserWithTheirRoles() {
        String first = service.create(user);

        RotatedRefreshToken rotated = service.rotate(first);

        assertThat(rotated.refreshToken()).isNotEqualTo(first);
        assertThat(rotated.user().getId()).isEqualTo(user.getId());
        // Read outside any transaction: fails with LazyInitializationException unless the roles were loaded.
        assertThat(rotated.user().getRoles()).extracting(Role::getName).containsExactly(RoleEnum.USER);
    }

    @Test
    void theNewTokenCanBeRotatedAgainSoASessionCanLastIndefinitelyWhileActive() {
        String first = service.create(user);
        String second = service.rotate(first).refreshToken();
        String third = service.rotate(second).refreshToken();

        assertThat(service.rotate(third).refreshToken()).isNotBlank();
    }

    // The case the whole design exists for. The stolen token is replayed after the real client has
    // already rotated it. Both the replay and the newest token of the family must stop working, and that
    // only holds if the revocation was committed even though an exception was thrown right after it.
    @Test
    void replayingAnUsedTokenRevokesTheWholeFamilyEvenTheNewestToken() {
        String first = service.create(user);
        String second = service.rotate(first).refreshToken();

        assertThatThrownBy(() -> service.rotate(first)).isInstanceOf(GeneralException.class);

        assertRejected(() -> service.rotate(second));
    }

    @Test
    void aReplayOnlyEndsThatLoginNotTheOthersOfTheSameUser() {
        String laptop = service.create(user);
        String phone = service.create(user);
        service.rotate(laptop);

        assertThatThrownBy(() -> service.rotate(laptop)).isInstanceOf(GeneralException.class);

        assertThat(service.rotate(phone).refreshToken()).isNotBlank();
    }

    @Test
    void logoutEndsTheLoginIncludingTokensIssuedByRotation() {
        String first = service.create(user);
        String second = service.rotate(first).refreshToken();

        service.revoke(second);

        assertRejected(() -> service.rotate(second));
        assertRejected(() -> service.rotate(first));
    }

    @Test
    void aTokenCannotBeUsedOnceItsUserIsDisabled() {
        String token = service.create(user);
        user.setEnabled(false);
        userRepository.save(user);

        assertRejected(() -> service.rotate(token));
    }

    // Two requests carrying the same token at the same moment: exactly one may win.
    @Test
    void whenTheSameTokenIsUsedTwiceAtOnceExactlyOneSucceeds() throws Exception {
        String token = service.create(user);
        int threads = 6;
        CountDownLatch go = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                Callable<Boolean> attempt = () -> {
                    go.await();
                    try {
                        service.rotate(token);
                        return true;
                    } catch (GeneralException e) {
                        return false;
                    }
                };
                results.add(pool.submit(attempt));
            }
            go.countDown();

            int successes = 0;
            for (Future<Boolean> result : results) {
                if (result.get()) {
                    successes++;
                }
            }
            assertThat(successes).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    private void assertRejected(Runnable action) {
        assertThatThrownBy(action::run)
                .isInstanceOfSatisfying(GeneralException.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN));
    }
}
