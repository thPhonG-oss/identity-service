package com.example.identity_service.service.authentication;

import com.example.identity_service.model.User;

/**
 * Result of using a refresh token.
 *
 * @param user         the owner of the token, with their roles loaded
 * @param refreshToken the new token, in clear text. This is the only moment it exists in clear text.
 */
public record RotatedRefreshToken(User user, String refreshToken) {
}
