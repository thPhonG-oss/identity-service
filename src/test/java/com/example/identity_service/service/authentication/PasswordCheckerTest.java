package com.example.identity_service.service.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.identity_service.model.User;
import com.example.identity_service.service.authentication.PasswordChecker.Result;

class PasswordCheckerTest {

    private static final String PASSWORD = "S3cure-pass!";

    // A spy, to see that a password is checked whatever the user is.
    private final PasswordEncoder encoder = spy(PasswordEncoderFactories.createDelegatingPasswordEncoder());
    private final PasswordChecker checker = new PasswordChecker(encoder);

    @Test
    void theRightPasswordMatches() {
        assertThat(checker.check(userWithHash(encoder.encode(PASSWORD)), PASSWORD)).isEqualTo(Result.MATCH);
    }

    @Test
    void aWrongPasswordDoesNot() {
        assertThat(checker.check(userWithHash(encoder.encode(PASSWORD)), "other")).isEqualTo(Result.WRONG_PASSWORD);
    }

    @Test
    void noUserIsUnknown() {
        assertThat(checker.check(null, PASSWORD)).isEqualTo(Result.UNKNOWN_USER);
    }

    @Test
    void aUserWithoutAPasswordHasNoPasswordWhateverIsTyped() {
        for (String hash : new String[] { null, "", "   " }) {
            assertThat(checker.check(userWithHash(hash), PASSWORD)).isEqualTo(Result.NO_PASSWORD);
        }
    }

    // The point of the dummy hash: every outcome costs a hash comparison, so the time does not tell them apart.
    @Test
    void aPasswordIsCheckedInEveryCase() {
        User real = userWithHash(encoder.encode(PASSWORD));
        for (User user : new User[] { real, null, userWithHash(null), userWithHash("") }) {
            clearInvocations(encoder);

            checker.check(user, PASSWORD);

            verify(encoder).matches(eq(PASSWORD), anyString());
        }
    }

    private static User userWithHash(String hash) {
        return User.builder().email("user@example.com").passwordHash(hash).build();
    }
}
