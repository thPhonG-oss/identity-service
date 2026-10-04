package com.example.identity_service.config;

import com.example.identity_service.exception.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Answers a request that needs authentication but has none. Spring Security's ExceptionTranslationFilter
 * calls it, which is why it is the place for the 401 that the controller advice can never produce:
 * filters run before the DispatcherServlet, so @RestControllerAdvice does not see their errors.
 *
 * The body is the same {@link com.example.identity_service.model.dto.response.ErrorResponse} as every
 * other error. The code says why: TOKEN_EXPIRED or INVALID_TOKEN when {@link JwtAuthenticationFilter}
 * rejected a token, UNAUTHENTICATED when there was none.
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ErrorResponseWriter errorResponseWriter;

    public JwtAuthenticationEntryPoint(ErrorResponseWriter errorResponseWriter) {
        this.errorResponseWriter = errorResponseWriter;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        ErrorCode errorCode = request.getAttribute(JwtAuthenticationFilter.TOKEN_ERROR_ATTRIBUTE) instanceof ErrorCode code
                ? code
                : ErrorCode.UNAUTHENTICATED;

        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate(errorCode));
        errorResponseWriter.write(request, response, errorCode);
    }

    // RFC 6750: a 401 names the scheme. When a token was sent and refused it also says so; when no
    // credentials were sent at all it must not carry an error code.
    private static String wwwAuthenticate(ErrorCode errorCode) {
        return switch (errorCode) {
            case TOKEN_EXPIRED -> "Bearer error=\"invalid_token\", error_description=\"The access token expired\"";
            case INVALID_TOKEN -> "Bearer error=\"invalid_token\"";
            default -> "Bearer";
        };
    }
}
