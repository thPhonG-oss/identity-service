package com.example.identity_service.service.impl;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.mapper.UserMapper;
import com.example.identity_service.model.User;
import com.example.identity_service.model.dto.response.UserDtoResponse;
import com.example.identity_service.repository.UserRepository;
import com.example.identity_service.service.UserService;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;

    public UserServiceImpl(UserRepository userRepository, UserMapper userMapper) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
    }

    @Override
    public UserDtoResponse getUserInfo(UUID userId) {
        User user  = userRepository.findById(userId).orElseThrow(() -> new GeneralException(ErrorCode.USER_NOT_FOUND));

        return userMapper.toUserReponse(user);
    }
}
