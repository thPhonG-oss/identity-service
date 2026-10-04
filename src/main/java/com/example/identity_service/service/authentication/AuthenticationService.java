package com.example.identity_service.service.authentication;

import com.example.identity_service.controller.dto.LoginRequest;
import com.example.identity_service.controller.dto.LoginResponse;
import com.example.identity_service.model.dto.request.UserCreationRequest;
import com.example.identity_service.model.dto.response.UserResponse;

public interface AuthenticationService {
    UserResponse register(UserCreationRequest userCreationRequest);

    LoginResponse login(LoginRequest loginRequest);
}
