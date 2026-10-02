package com.example.identity_service.service;

import com.example.identity_service.model.dto.request.UserCreationRequest;
import com.example.identity_service.model.dto.response.UserResponse;

import java.util.UUID;

public interface UserService {
    UserResponse getUserInfo(UUID userId);

    UserResponse createUser(UserCreationRequest userCreationRequest);
}
