package com.example.identity_service.exception;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.example.identity_service.controller.UserController;
import com.example.identity_service.service.UserService;

// Security filters are off here: this test is about how exceptions are rendered, not about who may call.
@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
class GlobalExceptionHandlerTest {

    private static final String USER_URL = "/api/v1/users/{id}";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private UserService userService;

    @Test
    void generalExceptionUsesItsErrorCode() throws Exception {
        when(userService.getUserInfo(any())).thenThrow(new GeneralException(ErrorCode.USER_NOT_FOUND));

        mockMvc.perform(get(USER_URL, UUID.randomUUID()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.code").value(1001))
                .andExpect(jsonPath("$.message").value("User not found"))
                .andExpect(jsonPath("$.path").value(org.hamcrest.Matchers.startsWith("/api/v1/users/")))
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.errors").doesNotExist());
    }

    @Test
    void malformedUuidIsBadRequestNotServerError() throws Exception {
        mockMvc.perform(get(USER_URL, "not-a-uuid"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(9001));
    }

    @Test
    void unknownRouteIsNotFoundNotServerError() throws Exception {
        mockMvc.perform(get("/api/v1/does-not-exist"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(9003));
    }

    @Test
    void wrongMethodIsMethodNotAllowedAndKeepsAllowHeader() throws Exception {
        mockMvc.perform(post(USER_URL, UUID.randomUUID()))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().string("Allow", org.hamcrest.Matchers.containsString("GET")))
                .andExpect(jsonPath("$.code").value(9004));
    }

    @Test
    void badCredentialsAreUnauthorizedWithAGenericMessage() throws Exception {
        when(userService.getUserInfo(any())).thenThrow(new BadCredentialsException("user 'x' not found"));

        mockMvc.perform(get(USER_URL, UUID.randomUUID()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value(2001))
                .andExpect(jsonPath("$.message").value("Invalid username or password"));
    }

    @Test
    void accessDeniedIsForbiddenNotServerError() throws Exception {
        when(userService.getUserInfo(any())).thenThrow(new AccessDeniedException("nope"));

        mockMvc.perform(get(USER_URL, UUID.randomUUID()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(2003));
    }

    @Test
    void unexpectedExceptionDoesNotLeakItsMessage() throws Exception {
        when(userService.getUserInfo(any())).thenThrow(new IllegalStateException("db password is hunter2"));

        mockMvc.perform(get(USER_URL, UUID.randomUUID()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value(9000))
                .andExpect(jsonPath("$.message").value("Internal server error"));
    }
}
