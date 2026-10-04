package com.example.identity_service.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import com.example.identity_service.exception.ErrorCode;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class JwtAuthenticationEntryPointTest {

    private final JsonMapper jsonMapper = JsonMapper.builder().build();
    private final JwtAuthenticationEntryPoint entryPoint = new JwtAuthenticationEntryPoint(new ErrorResponseWriter(jsonMapper));

    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users/1");
    private final MockHttpServletResponse response = new MockHttpServletResponse();

    @Test
    void noCredentialsGivesUnauthenticatedWithAPlainBearerChallenge() throws Exception {
        entryPoint.commence(request, response, new InsufficientAuthenticationException("no token"));

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
        JsonNode body = bodyOf(response);
        assertThat(body.get("status").asInt()).isEqualTo(401);
        assertThat(body.get("code").asInt()).isEqualTo(ErrorCode.UNAUTHENTICATED.getCode());
        assertThat(body.get("message").asString()).isEqualTo("Authentication is required");
        assertThat(body.get("path").asString()).isEqualTo("/api/v1/users/1");
        assertThat(body.has("errors")).isFalse();
    }

    @Test
    void anExpiredTokenIsReportedAsExpired() throws Exception {
        request.setAttribute(JwtAuthenticationFilter.TOKEN_ERROR_ATTRIBUTE, ErrorCode.TOKEN_EXPIRED);

        entryPoint.commence(request, response, new InsufficientAuthenticationException("expired"));

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).contains("invalid_token").contains("expired");
        assertThat(bodyOf(response).get("code").asInt()).isEqualTo(ErrorCode.TOKEN_EXPIRED.getCode());
    }

    @Test
    void aRejectedTokenIsReportedAsInvalid() throws Exception {
        request.setAttribute(JwtAuthenticationFilter.TOKEN_ERROR_ATTRIBUTE, ErrorCode.INVALID_TOKEN);

        entryPoint.commence(request, response, new InsufficientAuthenticationException("invalid"));

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer error=\"invalid_token\"");
        assertThat(bodyOf(response).get("code").asInt()).isEqualTo(ErrorCode.INVALID_TOKEN.getCode());
    }

    @Test
    void theResponseIsUtf8Json() throws Exception {
        entryPoint.commence(request, response, new InsufficientAuthenticationException("no token"));

        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getCharacterEncoding()).isEqualToIgnoringCase("UTF-8");
    }

    private JsonNode bodyOf(MockHttpServletResponse servletResponse) throws Exception {
        return jsonMapper.readTree(servletResponse.getContentAsString());
    }
}
