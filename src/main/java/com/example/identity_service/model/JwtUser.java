package com.example.identity_service.model;

import java.util.List;
import java.util.UUID;

/**
 * The identity carried by a verified access token: who the user is and what they may do.
 * It is built from the token claims alone, so reading it needs no database access.
 *
 * @param id          the "sub" claim, the id of the user
 * @param authorities the "scope" claim split into values, e.g. ["ROLE_USER", "ROLE_ADMIN"]
 */
public record JwtUser(UUID id, List<String> authorities) {
}
