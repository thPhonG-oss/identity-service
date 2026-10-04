package com.example.identity_service.config;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.model.dto.response.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Writes an {@link ErrorResponse} straight to the servlet response.
 *
 * Errors raised inside Spring Security's filters never reach the controller advice, because filters run
 * before the DispatcherServlet. The entry point (401) and the access denied handler (403) both use this,
 * so they answer in exactly the same shape as GlobalExceptionHandler.
 */
@Component
public class ErrorResponseWriter {

    private final JsonMapper jsonMapper;

    public ErrorResponseWriter(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    public void write(HttpServletRequest request, HttpServletResponse response, ErrorCode errorCode)
            throws IOException {
        response.setStatus(errorCode.getHttpStatus().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        ErrorResponse body = new ErrorResponse(
                errorCode.getHttpStatus().value(),
                errorCode.getCode(),
                errorCode.getMessage(),
                Instant.now(),
                request.getRequestURI(),
                null);
        jsonMapper.writeValue(response.getOutputStream(), body);
    }
}
