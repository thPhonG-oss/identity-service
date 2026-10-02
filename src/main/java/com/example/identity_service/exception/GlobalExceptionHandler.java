package com.example.identity_service.exception;

import java.time.Instant;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.example.identity_service.model.dto.response.ErrorResponse;

import lombok.extern.slf4j.Slf4j;

/**
 * Turns every exception into an {@link ErrorResponse}.
 *
 * Extends ResponseEntityExceptionHandler so Spring MVC's own errors (404 for unknown routes,
 * 405, 415, malformed JSON, ...) keep their correct status. Without it, the catch-all
 * handler below would turn them into 500s.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(GeneralException.class)
    public ResponseEntity<Object> handleGeneralException(GeneralException ex, WebRequest request) {
        ErrorCode errorCode = ex.getErrorCode();
        log.debug("Business error {}: {}", errorCode, ex.getMessage());
        return build(errorCode.getHttpStatus(), errorCode, ex.getMessage(), null, HttpHeaders.EMPTY, request);
    }

    // Always answer with the same message, whether the username or the password was wrong.
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Object> handleBadCredentials(BadCredentialsException ex, WebRequest request) {
        log.debug("Bad credentials: {}", ex.getMessage());
        ErrorCode errorCode = ErrorCode.INVALID_CREDENTIALS;
        return build(errorCode.getHttpStatus(), errorCode, errorCode.getMessage(), null, HttpHeaders.EMPTY, request);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Object> handleAuthentication(AuthenticationException ex, WebRequest request) {
        log.debug("Authentication failed: {}", ex.getMessage());
        ErrorCode errorCode = ErrorCode.UNAUTHENTICATED;
        return build(errorCode.getHttpStatus(), errorCode, errorCode.getMessage(), null, HttpHeaders.EMPTY, request);
    }

    // Thrown by method security (@PreAuthorize) from inside controllers. Without this handler the
    // catch-all below would answer 500 instead of 403.
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccessDenied(AccessDeniedException ex, WebRequest request) {
        log.debug("Access denied: {}", ex.getMessage());
        ErrorCode errorCode = ErrorCode.ACCESS_DENIED;
        return build(errorCode.getHttpStatus(), errorCode, errorCode.getMessage(), null, HttpHeaders.EMPTY, request);
    }

    // Never send the exception message to the client: it may expose internals.
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleUnexpected(Exception ex, WebRequest request) {
        log.error("Unhandled exception", ex);
        ErrorCode errorCode = ErrorCode.INTERNAL_ERROR;
        return build(errorCode.getHttpStatus(), errorCode, errorCode.getMessage(), null, HttpHeaders.EMPTY, request);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<ErrorResponse.FieldViolation> violations = ex.getBindingResult().getAllErrors().stream()
                .map(error -> new ErrorResponse.FieldViolation(
                        error instanceof FieldError fieldError ? fieldError.getField() : error.getObjectName(),
                        error.getDefaultMessage()))
                .toList();
        ErrorCode errorCode = ErrorCode.VALIDATION_FAILED;
        return build(status, errorCode, errorCode.getMessage(), violations, headers, request);
    }

    // Every other Spring MVC exception ends up here, with a ProblemDetail body we replace.
    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers,
            HttpStatusCode statusCode, WebRequest request) {
        ErrorCode errorCode = ErrorCode.fromHttpStatus(statusCode);
        if (statusCode.is5xxServerError()) {
            log.error("Server error", ex);
        }
        String message = statusCode.is4xxClientError() && body instanceof ProblemDetail problem
                && problem.getDetail() != null ? problem.getDetail() : errorCode.getMessage();
        return build(statusCode, errorCode, message, null, headers, request);
    }

    private ResponseEntity<Object> build(HttpStatusCode status, ErrorCode errorCode, String message,
            List<ErrorResponse.FieldViolation> errors, HttpHeaders headers, WebRequest request) {
        ErrorResponse body = new ErrorResponse(
                status.value(), errorCode.getCode(), message, Instant.now(), pathOf(request), errors);
        return ResponseEntity.status(status).headers(headers).body(body);
    }

    private static String pathOf(WebRequest request) {
        return request instanceof ServletWebRequest servletRequest ? servletRequest.getRequest().getRequestURI() : null;
    }
}
