package com.example.identity_service.service.authentication;

import org.springframework.security.core.Authentication;

import com.example.identity_service.model.JwtUser;

public interface JwtService {
    /** Creates a signed access token for an authenticated user. */
    String generateAccessToken(Authentication authentication);

    /**
     * Tells whether the token is acceptable: well formed, signed by us, issued by us and not expired.
     * A bad token gives {@code false}, never an exception.
     */
    boolean validateToken(String token);

    /**
     * Verifies the token like {@link #validateToken} and returns the user it identifies, read from the
     * claims only (no database access).
     *
     * @throws com.example.identity_service.exception.GeneralException with INVALID_TOKEN or TOKEN_EXPIRED
     *                                                                 when the token is not acceptable
     */
    JwtUser getUserFromToken(String token);
}
