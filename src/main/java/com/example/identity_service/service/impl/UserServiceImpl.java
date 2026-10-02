package com.example.identity_service.service.impl;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.mapper.UserMapper;
import com.example.identity_service.model.User;
import com.example.identity_service.model.dto.request.UserCreationRequest;
import com.example.identity_service.model.dto.response.UserResponse;
import com.example.identity_service.repository.UserRepository;
import com.example.identity_service.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@Slf4j
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, UserMapper userMapper, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserResponse getUserInfo(UUID userId) {
        User user  = userRepository.findById(userId).orElseThrow(() -> new GeneralException(ErrorCode.USER_NOT_FOUND));

        return userMapper.toUserReponse(user);
    }

    @Override
    public UserResponse createUser(UserCreationRequest userCreationRequest) {
        final String username = userCreationRequest.getUsername();
        final String email = userCreationRequest.getEmail();
        final String password = userCreationRequest.getPassword();

        if(userRepository.existsByUsername(username)) {
            throw new GeneralException(ErrorCode.USERNAME_ALREADY_EXISTS);
        }

        if(userRepository.existsByEmail(email)) {
            throw new GeneralException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        final User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(password));

        User savedUser = userRepository.save(user);

        log.info("Create user successfully with userId: {}", savedUser.getId());

        return userMapper.toUserReponse(user);
    }
}
