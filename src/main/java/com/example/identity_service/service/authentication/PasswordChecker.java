package com.example.identity_service.service.authentication;

import com.example.identity_service.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.UUID;

/**
 * Checks a password against a user, in the same amount of work whoever the user is. Used wherever someone
 * proves they know an account's password: signing in, and confirming a link with an external account.
 */
@Component
public class PasswordChecker {

    public enum Result {
        MATCH, UNKNOWN_USER, NO_PASSWORD, WRONG_PASSWORD
    }

    private final PasswordEncoder passwordEncoder;

    // A valid hash of a random password nobody knows, made by the same encoder as real hashes so that
    // checking against it costs the same. Used when there is nothing real to check against.
    private final String unknownUserPasswordHash;

    public PasswordChecker(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.unknownUserPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    /**
     * @param user the account, or {@code null} when there is none
     * @return why the check failed, for the log only; callers must give the user one answer for all of them
     */
    public Result check(User user, String rawPassword) {
        // The password is checked on EVERY attempt, even when there is no user. Hashing is slow on purpose
        // (about 100 ms for bcrypt); skipping it for an unknown email would make that answer much faster,
        // and the response time alone would tell an attacker which emails are registered.
        // A user without a password (one who signs in only with Google) is treated like an unknown email:
        // the same dummy hash is checked, so such an account cannot be told apart by the response or its time.
        // A blank hash counts as "no password" too: the encoder cannot read it and would throw, not answer false.
        boolean hasPassword = user != null && StringUtils.hasText(user.getPasswordHash());
        String hashToCheck = hasPassword ? user.getPasswordHash() : unknownUserPasswordHash;
        boolean matches = passwordEncoder.matches(rawPassword, hashToCheck);

        if (user == null) {
            return Result.UNKNOWN_USER;
        }
        if (!hasPassword) {
            return Result.NO_PASSWORD;
        }
        return matches ? Result.MATCH : Result.WRONG_PASSWORD;
    }
}
