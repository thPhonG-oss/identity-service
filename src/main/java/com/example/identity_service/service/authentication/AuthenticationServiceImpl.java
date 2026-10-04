package com.example.identity_service.service.authentication;

import com.example.identity_service.controller.dto.LoginRequest;
import com.example.identity_service.controller.dto.LoginResponse;
import com.example.identity_service.exception.ErrorCode;
import com.example.identity_service.exception.GeneralException;
import com.example.identity_service.model.CustomUserDetails;
import com.example.identity_service.model.JwtProperties;
import com.example.identity_service.model.User;
import com.example.identity_service.model.dto.request.UserCreationRequest;
import com.example.identity_service.model.dto.response.UserResponse;
import com.example.identity_service.repository.UserRepository;
import com.example.identity_service.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {
    private static final String TOKEN_TYPE = "Bearer";

    private final UserService userService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    // A valid hash of a random password nobody knows, made by the same encoder as real hashes so that
    // checking against it costs the same. Used when the email does not exist, see login().
    private final String unknownUserPasswordHash;

    public AuthenticationServiceImpl(UserService userService, UserRepository userRepository,
            PasswordEncoder passwordEncoder, JwtService jwtService, JwtProperties jwtProperties) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
        this.unknownUserPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    @Override
    @Transactional(
            rollbackFor = Exception.class,
            propagation = Propagation.REQUIRED
    )
    public UserResponse register(UserCreationRequest userCreationRequest) {
        return userService.createUser(userCreationRequest);
    }

    @Override
    public LoginResponse login(final LoginRequest loginRequest) {
        User user = userRepository.findByEmail(loginRequest.getEmail()).orElse(null);

        // The password is checked on EVERY attempt, even when the email does not exist. Hashing is slow
        // on purpose (about 100 ms for bcrypt); skipping it for an unknown email would make that answer
        // much faster, and the response time alone would tell an attacker which emails are registered.
        String hashToCheck = user != null ? user.getPasswordHash() : unknownUserPasswordHash;
        boolean passwordMatches = passwordEncoder.matches(loginRequest.getPassword(), hashToCheck);

        // One error for every failure. The account state is checked only after the password, so a
        // disabled account is not revealed to someone who does not know the password either.
        if (user == null) {
            throw rejected("unknown email");
        }
        if (!passwordMatches) {
            throw rejected("wrong password");
        }
        if (!user.isEnabled()) {
            throw rejected("account disabled");
        }

        CustomUserDetails principal = new CustomUserDetails(user);
        Authentication authentication =
                UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());

        String accessToken = jwtService.generateAccessToken(authentication);

        return new LoginResponse(true, accessToken, TOKEN_TYPE, jwtProperties.accessTokenTtl().toSeconds());
    }

    // The reason is for the operators' log only. The email is not logged: it is personal data.
    private GeneralException rejected(String reason) {
        log.warn("Login rejected: {}", reason);
        return new GeneralException(ErrorCode.INVALID_CREDENTIALS);
    }
}
