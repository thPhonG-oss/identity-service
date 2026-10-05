package com.example.identity_service.service.authentication;

import com.example.identity_service.controller.dto.LoginRequest;
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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {
    private static final String TOKEN_TYPE = "Bearer";

    private final UserService userService;
    private final UserRepository userRepository;
    private final PasswordChecker passwordChecker;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final RefreshTokenService refreshTokenService;

    public AuthenticationServiceImpl(UserService userService, UserRepository userRepository,
            PasswordChecker passwordChecker, JwtService jwtService, JwtProperties jwtProperties,
            RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.passwordChecker = passwordChecker;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
        this.refreshTokenService = refreshTokenService;
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
    public AuthTokens login(final LoginRequest loginRequest) {
        User user = userRepository.findByEmail(loginRequest.getEmail()).orElse(null);

        // One error for every failure. The account state is checked only after the password, so a
        // disabled account is not revealed to someone who does not know the password either.
        PasswordChecker.Result result = passwordChecker.check(user, loginRequest.getPassword());
        switch (result) {
            case UNKNOWN_USER -> throw rejected("unknown email");
            case NO_PASSWORD -> throw rejected("account has no password");
            case WRONG_PASSWORD -> throw rejected("wrong password");
            case MATCH -> {
            }
        }
        if (!user.isEnabled()) {
            throw rejected("account disabled");
        }

        return tokensFor(user, refreshTokenService.create(user));
    }

    @Override
    public AuthTokens loginAs(final User user) {
        if (!user.isEnabled()) {
            throw rejected("account disabled");
        }
        return tokensFor(user, refreshTokenService.create(user));
    }

    // Every use of a refresh token replaces it. The roles in the new access token are read from the
    // database again, so a change of roles takes effect at the next refresh at the latest.
    @Override
    public AuthTokens refresh(final String refreshToken) {
        RotatedRefreshToken rotated = refreshTokenService.rotate(refreshToken);

        return tokensFor(rotated.user(), rotated.refreshToken());
    }

    @Override
    public void logout(final String refreshToken) {
        refreshTokenService.revoke(refreshToken);
    }

    private AuthTokens tokensFor(User user, String refreshToken) {
        CustomUserDetails principal = new CustomUserDetails(user);
        Authentication authentication =
                UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());

        String accessToken = jwtService.generateAccessToken(authentication);

        return new AuthTokens(accessToken, refreshToken, TOKEN_TYPE, jwtProperties.accessTokenTtl().toSeconds());
    }

    // The reason is for the operators' log only. The email is not logged: it is personal data.
    private GeneralException rejected(String reason) {
        log.warn("Login rejected: {}", reason);
        return new GeneralException(ErrorCode.INVALID_CREDENTIALS);
    }
}
