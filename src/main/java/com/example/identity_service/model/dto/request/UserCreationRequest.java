package com.example.identity_service.model.dto.request;

import com.example.identity_service.validation.StrongPassword;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class UserCreationRequest {

    // No '@' allowed, so a username can never be mistaken for an email when logging in.
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @NotBlank(message = "Email is required")
    @Size(max = 255, message = "Email must be at most 255 characters")
    @Email(message = "Email is not valid")
    private String email;

    // Raw password. Strength rules, including the 72-byte BCrypt limit, live in @StrongPassword.
    @NotBlank(message = "Password is required")
    @StrongPassword
    private String password;
}
