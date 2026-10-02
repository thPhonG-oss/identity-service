package com.example.identity_service.model.dto.response;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Body of every error response.
 *
 * @param status    HTTP status code
 * @param code      application error code, see ErrorCode
 * @param errors    per-field details, only present for validation failures
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
        int status,
        int code,
        String message,
        Instant timestamp,
        String path,
        List<FieldViolation> errors) {

    public record FieldViolation(String field, String message) {
    }
}
