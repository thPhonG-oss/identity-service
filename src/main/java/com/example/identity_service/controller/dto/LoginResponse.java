package com.example.identity_service.controller.dto;

import com.example.identity_service.service.authentication.AuthTokens;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Body of a login or refresh response. It has no refresh token: that one travels only in an HttpOnly
 * cookie, so a script injected into the page (XSS) cannot steal it.
 */
@Getter
@AllArgsConstructor
public class LoginResponse {
    private boolean authenticated;
    private String accessToken;
    /** How the access token is sent back: {@code Authorization: Bearer <accessToken>}. */
    private String tokenType;
    /** Lifetime of the access token in seconds, the unit OAuth2 uses for expires_in. */
    private long expiresIn;

    public static LoginResponse from(AuthTokens tokens) {
        return new LoginResponse(true, tokens.accessToken(), tokens.tokenType(), tokens.expiresIn());
    }
}
