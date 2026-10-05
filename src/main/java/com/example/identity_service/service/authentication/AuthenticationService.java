package com.example.identity_service.service.authentication;

import com.example.identity_service.controller.dto.LoginRequest;
import com.example.identity_service.model.User;
import com.example.identity_service.model.dto.request.UserCreationRequest;
import com.example.identity_service.model.dto.response.UserResponse;

public interface AuthenticationService {
    UserResponse register(UserCreationRequest userCreationRequest);

    AuthTokens login(LoginRequest loginRequest);

    /** Trades a refresh token for a new access token and a new refresh token. */
    AuthTokens refresh(String refreshToken);

    /** Ends the login the refresh token belongs to. */
    void logout(String refreshToken);

    /**
     * Issues the same tokens as {@link #login} for a user who has already been authenticated some other
     * way, e.g. by Google. No password is involved.
     */
    AuthTokens loginAs(User user);
}
