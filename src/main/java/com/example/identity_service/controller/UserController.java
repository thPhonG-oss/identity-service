package com.example.identity_service.controller;

import com.example.identity_service.model.dto.response.UserResponse;
import com.example.identity_service.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("api/v1/users")
@Slf4j
public class UserController {
    private final UserService userService;


    public UserController(UserService userService) {
        this.userService = userService;
    }

    // A user may read their own data; an admin may read anyone's. "principal" is the JwtUser that
    // JwtAuthenticationFilter put in the SecurityContext, so no database access is needed to decide.
    @PreAuthorize("hasRole('ADMIN') or #userId == principal.id()")
    @GetMapping("/{userId}")
    public ResponseEntity<UserResponse> getUserInfo(@PathVariable UUID userId){
        return ResponseEntity.ok(
          userService.getUserInfo(userId)
        );
    }
}
