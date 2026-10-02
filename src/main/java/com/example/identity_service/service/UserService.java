package com.example.identity_service.service;

import com.example.identity_service.model.dto.response.UserDtoResponse;

import java.util.UUID;

public interface UserService {
    UserDtoResponse getUserInfo(UUID userId);
}
