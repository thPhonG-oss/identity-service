package com.example.identity_service.controller;

import com.example.identity_service.controller.dto.LoginRequest;
import com.example.identity_service.controller.dto.LoginResponse;
import com.example.identity_service.model.dto.request.UserCreationRequest;
import com.example.identity_service.model.dto.response.UserResponse;
import com.example.identity_service.service.authentication.AuthenticationService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("api/v1/auth")
public class AuthController {

    private final AuthenticationService authenticationService;

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest loginRequest) {
        return ResponseEntity.ok(authenticationService.login(loginRequest));
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@RequestBody @Valid UserCreationRequest userCreationRequest) {
        return new ResponseEntity<>(
                authenticationService.register(userCreationRequest),
                HttpStatus.CREATED
        );
    }
}
