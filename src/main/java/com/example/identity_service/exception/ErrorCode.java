package com.example.identity_service.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

import lombok.Getter;

@Getter
public enum ErrorCode {
    // 1xxx: users
    USER_NOT_FOUND(1001, HttpStatus.NOT_FOUND, "User not found"),
    // 1002 was USERNAME_ALREADY_EXISTS. Codes are part of the API, so the number is left unused.
    EMAIL_ALREADY_EXISTS(1003, HttpStatus.CONFLICT, "Email already exists"),

    // 2xxx: authentication and authorization
    // INVALID_CREDENTIALS must not reveal whether the email or the password was wrong.
    INVALID_CREDENTIALS(2001, HttpStatus.UNAUTHORIZED, "Invalid email or password"),
    UNAUTHENTICATED(2002, HttpStatus.UNAUTHORIZED, "Authentication is required"),
    ACCESS_DENIED(2003, HttpStatus.FORBIDDEN, "You do not have permission to access this resource"),
    INVALID_TOKEN(2004, HttpStatus.UNAUTHORIZED, "Token is invalid"),
    TOKEN_EXPIRED(2005, HttpStatus.UNAUTHORIZED, "Token has expired"),

    // 9xxx: general
    INTERNAL_ERROR(9000, HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error"),
    BAD_REQUEST(9001, HttpStatus.BAD_REQUEST, "Bad request"),
    VALIDATION_FAILED(9002, HttpStatus.BAD_REQUEST, "Validation failed"),
    RESOURCE_NOT_FOUND(9003, HttpStatus.NOT_FOUND, "Resource not found"),
    METHOD_NOT_ALLOWED(9004, HttpStatus.METHOD_NOT_ALLOWED, "Method not allowed"),
    UNSUPPORTED_MEDIA_TYPE(9005, HttpStatus.UNSUPPORTED_MEDIA_TYPE, "Unsupported media type"),
    ROLE_NOT_FOUND(9006, HttpStatus.BAD_REQUEST, "Role not found");

    private final int code;
    private final HttpStatus httpStatus;
    private final String message;

    ErrorCode(int code, HttpStatus httpStatus, String message) {
        this.code = code;
        this.httpStatus = httpStatus;
        this.message = message;
    }

    /** Maps the status of a framework-raised error (404, 405, ...) to the closest general code. */
    public static ErrorCode fromHttpStatus(HttpStatusCode status) {
        return switch (status.value()) {
            case 400 -> BAD_REQUEST;
            case 404 -> RESOURCE_NOT_FOUND;
            case 405 -> METHOD_NOT_ALLOWED;
            case 415 -> UNSUPPORTED_MEDIA_TYPE;
            default -> status.is5xxServerError() ? INTERNAL_ERROR : BAD_REQUEST;
        };
    }
}
