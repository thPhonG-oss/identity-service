package com.example.identity_service.controller.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoginResponse {
    private boolean authenticated;
    private String accessToken;
    /** How the token is sent back: {@code Authorization: Bearer <accessToken>}. */
    private String tokenType;
    /** Lifetime of the access token in seconds, the unit OAuth2 uses for expires_in. */
    private long expiresIn;
}
