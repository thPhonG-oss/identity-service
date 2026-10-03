package com.example.identity_service.service.impl;

import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.mapper.UserMapper;
import com.example.identity_service.model.Role;
import com.example.identity_service.model.RoleEnum;
import com.example.identity_service.model.User;
import com.example.identity_service.model.dto.request.UserCreationRequest;
import com.example.identity_service.model.dto.response.UserResponse;
import com.example.identity_service.repository.UserRepository;
import com.example.identity_service.service.RoleService;
import com.example.identity_service.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final RoleService roleService;

    public UserServiceImpl(UserRepository userRepository, UserMapper userMapper, PasswordEncoder passwordEncoder, RoleService roleService) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
        this.roleService = roleService;
    }

    @Override
    public UserResponse getUserInfo(UUID userId) {
        User user  = userRepository.findById(userId).orElseThrow(() -> new GeneralException(ErrorCode.USER_NOT_FOUND));

        return userMapper.toUserReponse(user);
    }

    @Override
    @Transactional(rollbackFor = Exception.class, propagation = Propagation.REQUIRED)
    public UserResponse createUser(UserCreationRequest userCreationRequest) {
        final String username = userCreationRequest.getUsername();
        final String email = userCreationRequest.getEmail();
        final String password = userCreationRequest.getPassword();
        final List<RoleEnum> roleEnumList = userCreationRequest.getRoles();

        final Set<Role> roles = convertRoleEnumToRole(roleEnumList);
        final Set<Role> defaultRoleList = Set.of(roleService.getRoleByName(RoleEnum.USER));

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

        // handle role assignment
        if(roleEnumList.isEmpty() || roles.isEmpty()) {
            log.warn("The role list when creating user is empty");
            user.setRoles(defaultRoleList);
        } else {
            user.setRoles(roles);
        }

        User savedUser = userRepository.save(user);

        log.info("Create user successfully with userId: {}", savedUser.getId());

        return userMapper.toUserReponse(user);
    }

    private Set<Role> convertRoleEnumToRole(List<RoleEnum> roleEnums) {
        return roleEnums.stream()
                .map(roleEnum -> {
                    try {
                        return roleService.getRoleByName(roleEnum);
                    } catch (GeneralException ex) {
                        log.warn("Can not find the role: {}", roleEnum);
                    }
                    return null;
                }).collect(Collectors.toSet());
    }
}
