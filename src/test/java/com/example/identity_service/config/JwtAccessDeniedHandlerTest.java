package com.example.identity_service.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

import com.example.identity_service.exception.ErrorCode;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class JwtAccessDeniedHandlerTest {

    private final JsonMapper jsonMapper = JsonMapper.builder().build();
    private final JwtAccessDeniedHandler handler = new JwtAccessDeniedHandler(new ErrorResponseWriter(jsonMapper));

    @Test
    void answersWith403AndTheStandardErrorBody() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/roles");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handle(request, response, new AccessDeniedException("Access Denied"));

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentType()).startsWith("application/json");
        JsonNode body = jsonMapper.readTree(response.getContentAsString());
        assertThat(body.get("status").asInt()).isEqualTo(403);
        assertThat(body.get("code").asInt()).isEqualTo(ErrorCode.ACCESS_DENIED.getCode());
        assertThat(body.get("message").asString()).isEqualTo(ErrorCode.ACCESS_DENIED.getMessage());
        assertThat(body.get("path").asString()).isEqualTo("/api/v1/roles");
    }

    @Test
    void doesNotRepeatTheReasonFromTheException() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handle(new MockHttpServletRequest("GET", "/x"), response,
                new AccessDeniedException("internal detail: expression hasRole('ADMIN') was false"));

        assertThat(response.getContentAsString()).doesNotContain("internal detail");
    }
}
