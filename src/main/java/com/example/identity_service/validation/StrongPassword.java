package com.example.identity_service.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

/**
 * Validates password strength: minimum length, at least one uppercase letter, lowercase letter,
 * digit and special character, no whitespace, and a maximum size in bytes.
 *
 * {@code null} is considered valid, combine with {@code @NotBlank} to require a value.
 * Every broken rule is reported as its own violation.
 */
@Documented
@Constraint(validatedBy = StrongPasswordValidator.class)
@Target({ ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface StrongPassword {

    String message() default "Password is not strong enough";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    /** Minimum length in characters. */
    int min() default 8;

    /** Maximum size in UTF-8 bytes. BCrypt only uses the first 72 bytes, the rest is silently ignored. */
    int maxBytes() default 72;
}
