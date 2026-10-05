package com.example.identity_service.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

/** The password of the existing account, to confirm that the person linking is its owner. */
@Getter
public class LinkAccountRequest {
    @NotBlank(message = "password is required")
    private String password;
}
