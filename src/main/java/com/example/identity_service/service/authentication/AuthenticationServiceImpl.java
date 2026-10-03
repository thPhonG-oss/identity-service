package com.example.identity_service.service.authentication;

import com.example.identity_service.model.dto.request.UserCreationRequest;
import com.example.identity_service.model.dto.response.UserResponse;
import com.example.identity_service.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserService userService;

    public AuthenticationServiceImpl(UserService userService) {
        this.userService = userService;
    }

    @Override
    @Transactional(
            rollbackFor = Exception.class,
            propagation = Propagation.REQUIRED
    )
    public UserResponse register(UserCreationRequest userCreationRequest) {
        log.info("Username: {}", userCreationRequest.getUsername());
        return userService.createUser(userCreationRequest);
    }
}
