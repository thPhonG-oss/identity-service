package com.example.identity_service.service.authentication;

/**
 * The two tokens a login or a refresh produces.
 *
 * They are kept apart on purpose: the access token goes to the JavaScript of the SPA in the response
 * body, while the refresh token is only ever put in an HttpOnly cookie, which JavaScript cannot read.
 * That is why this is not simply one response object with both inside.
 *
 * @param accessToken  short-lived JWT, sent as {@code Authorization: Bearer ...}
 * @param refreshToken long-lived opaque token, sent back by the browser in a cookie
 * @param tokenType    always {@code Bearer}
 * @param expiresIn    lifetime of the access token in seconds
 */
public record AuthTokens(String accessToken, String refreshToken, String tokenType, long expiresIn) {
}
