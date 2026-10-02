package com.example.identity_service.controller.dto;

import lombok.Getter;

@Getter
public class LoginResponse {
    private boolean authenticated;
    private String accessToken;
}
