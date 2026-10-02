package com.example.identity_service.validation;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {

    private int min;
    private int maxBytes;

    @Override
    public void initialize(StrongPassword constraint) {
        this.min = constraint.min();
        this.maxBytes = constraint.maxBytes();
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) {
            return true;
        }

        List<String> problems = new ArrayList<>();

        if (password.codePointCount(0, password.length()) < min) {
            problems.add("Password must be at least " + min + " characters long");
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
            problems.add("Password must be at most " + maxBytes + " bytes long");
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        boolean hasWhitespace = false;
        for (int i = 0; i < password.length(); ) {
            int codePoint = password.codePointAt(i);
            i += Character.charCount(codePoint);

            if (Character.isUpperCase(codePoint)) {
                hasUpper = true;
            } else if (Character.isLowerCase(codePoint)) {
                hasLower = true;
            } else if (Character.isDigit(codePoint)) {
                hasDigit = true;
            } else if (Character.isWhitespace(codePoint)) {
                hasWhitespace = true;
            } else if (!Character.isLetter(codePoint)) {
                hasSpecial = true;
            }
        }

        if (!hasUpper) {
            problems.add("Password must contain at least one uppercase letter");
        }
        if (!hasLower) {
            problems.add("Password must contain at least one lowercase letter");
        }
        if (!hasDigit) {
            problems.add("Password must contain at least one digit");
        }
        if (!hasSpecial) {
            problems.add("Password must contain at least one special character");
        }
        if (hasWhitespace) {
            problems.add("Password must not contain whitespace");
        }

        if (problems.isEmpty()) {
            return true;
        }

        // One violation per broken rule, so the client can show all of them at once.
        context.disableDefaultConstraintViolation();
        problems.forEach(problem -> context.buildConstraintViolationWithTemplate(problem).addConstraintViolation());
        return false;
    }
}
