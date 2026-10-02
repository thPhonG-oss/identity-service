package com.example.identity_service.service.authentication;

import com.example.identity_service.model.User;
import com.example.identity_service.model.dto.request.UserCreationRequest;
import com.example.identity_service.model.dto.response.UserResponse;
import com.example.identity_service.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserService userService;

    public AuthenticationServiceImpl(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserResponse register(UserCreationRequest userCreationRequest) {
        log.info("Username: {}", userCreationRequest.getUsername());
        return userService.createUser(userCreationRequest);
    }
}
