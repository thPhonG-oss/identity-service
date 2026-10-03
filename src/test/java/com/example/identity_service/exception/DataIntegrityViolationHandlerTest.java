package com.example.identity_service.exception;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.SQLException;
import java.util.UUID;

import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.example.identity_service.controller.UserController;
import com.example.identity_service.service.UserService;

// Checks how the handler maps database constraint names to HTTP responses.
@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
class DataIntegrityViolationHandlerTest {

    private static final String USER_URL = "/api/v1/users/{id}";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private UserService userService;

    @Test
    void duplicateUsernameIsConflict() throws Exception {
        failWithConstraint("uq_users_username_lower");

        mockMvc.perform(get(USER_URL, UUID.randomUUID()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(1002))
                .andExpect(jsonPath("$.message").value("Username already exists"));
    }

    @Test
    void duplicateEmailIsConflict() throws Exception {
        failWithConstraint("uq_users_email_lower");

        mockMvc.perform(get(USER_URL, UUID.randomUUID()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(1003))
                .andExpect(jsonPath("$.message").value("Email already exists"));
    }

    @Test
    void unmappedConstraintIsServerErrorAndLeaksNothing() throws Exception {
        failWithConstraint("some_other_constraint");

        mockMvc.perform(get(USER_URL, UUID.randomUUID()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value(9000))
                .andExpect(jsonPath("$.message").value("Internal server error"));
    }

    @Test
    void violationWithoutConstraintNameIsServerError() throws Exception {
        when(userService.getUserInfo(any()))
                .thenThrow(new DataIntegrityViolationException("null value in column \"email\""));

        mockMvc.perform(get(USER_URL, UUID.randomUUID()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value(9000));
    }

    private void failWithConstraint(String constraintName) {
        var cause = new ConstraintViolationException("duplicate key", new SQLException("duplicate key"), constraintName);
        when(userService.getUserInfo(any())).thenThrow(new DataIntegrityViolationException("could not execute", cause));
    }
}
