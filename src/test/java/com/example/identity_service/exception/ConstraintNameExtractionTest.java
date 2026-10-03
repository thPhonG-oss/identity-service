package com.example.identity_service.exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import com.example.identity_service.model.User;
import com.example.identity_service.repository.UserRepository;

// Reproduces the registration race against the real Postgres: the duplicate is only rejected when the
// transaction commits, exactly like UserServiceImpl.createUser. That is why each save runs in its own
// committed transaction instead of the rolled-back transaction a @DataJpaTest normally wraps tests in.
// Test data uses random names and is deleted afterwards, so the dev database is left as it was.
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("dev")
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class ConstraintNameExtractionTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private final String suffix = UUID.randomUUID().toString().substring(0, 8);
    private final String username = "race_" + suffix;
    private final String email = "race_" + suffix + "@example.com";

    @AfterEach
    void cleanUp() {
        inOwnTransaction(() -> {
            userRepository.findByUsername(username).ifPresent(userRepository::delete);
            userRepository.findByUsername(username + "_2").ifPresent(userRepository::delete);
            return null;
        });
    }

    @Test
    void duplicateUsernameReportsTheUsernameIndex() {
        inOwnTransaction(() -> userRepository.save(newUser(username, email)));

        assertThatThrownBy(() -> inOwnTransaction(
                () -> userRepository.save(newUser(username.toUpperCase(), "other_" + email))))
                .isInstanceOf(DataIntegrityViolationException.class)
                .satisfies(ex -> assertThat(GlobalExceptionHandler.constraintNameOf(ex))
                        .isEqualTo("uq_users_username_lower"));
    }

    @Test
    void duplicateEmailReportsTheEmailIndex() {
        inOwnTransaction(() -> userRepository.save(newUser(username, email)));

        assertThatThrownBy(() -> inOwnTransaction(
                () -> userRepository.save(newUser(username + "_2", email.toUpperCase()))))
                .isInstanceOf(DataIntegrityViolationException.class)
                .satisfies(ex -> assertThat(GlobalExceptionHandler.constraintNameOf(ex))
                        .isEqualTo("uq_users_email_lower"));
    }

    private <T> T inOwnTransaction(java.util.function.Supplier<T> work) {
        return new TransactionTemplate(transactionManager).execute(status -> work.get());
    }

    private static User newUser(String username, String email) {
        return User.builder().username(username).email(email).passwordHash("{test}not-a-real-hash").build();
    }
}
