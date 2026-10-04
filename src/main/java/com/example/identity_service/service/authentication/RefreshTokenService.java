package com.example.identity_service.service.authentication;

import com.example.identity_service.model.User;

public interface RefreshTokenService {

    /** Starts a new family for a fresh login. Returns the token in clear text; only its hash is stored. */
    String create(User user);

    /**
     * Uses a refresh token: it is retired and a new one is issued in the same family.
     *
     * @throws com.example.identity_service.exception.GeneralException with INVALID_REFRESH_TOKEN when the
     *         token is unknown, expired, already used, revoked, or belongs to a disabled account. A token
     *         that was already used also revokes its whole family, because it means a copy was stolen.
     */
    RotatedRefreshToken rotate(String refreshToken);

    /** Logs out: revokes the whole family of the token. An unknown token is ignored. */
    void revoke(String refreshToken);
}
