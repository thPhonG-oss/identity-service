package com.example.identity_service.model.dto.request;

import com.example.identity_service.validation.StrongPassword;

import jakarta.validation.constraints.*;
import lombok.Getter;


@Getter
public class UserCreationRequest {

    @NotBlank(message = "Email is required")
    @Size(max = 255, message = "Email must be at most 255 characters")
    @Email(message = "Email is not valid")
    private String email;

    // Raw password. Strength rules, including the 72-byte BCrypt limit, live in @StrongPassword.
    @NotBlank(message = "Password is required")
    @StrongPassword
    private String password;
}
