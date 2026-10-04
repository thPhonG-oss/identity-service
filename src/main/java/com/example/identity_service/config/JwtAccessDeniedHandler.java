package com.example.identity_service.config;

import com.example.identity_service.exception.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Answers 403 when a user who IS authenticated lacks the authority a URL rule asks for, e.g.
 * hasRole("ADMIN") in SecurityConfig. (The 401 for someone not authenticated is the entry point's job.)
 *
 * A denial raised by @PreAuthorize happens inside the controller call instead, and is answered by
 * GlobalExceptionHandler. Both give the same ACCESS_DENIED response.
 */
@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    private final ErrorResponseWriter errorResponseWriter;

    public JwtAccessDeniedHandler(ErrorResponseWriter errorResponseWriter) {
        this.errorResponseWriter = errorResponseWriter;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {
        errorResponseWriter.write(request, response, ErrorCode.ACCESS_DENIED);
    }
}
