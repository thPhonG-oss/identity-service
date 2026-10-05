package com.example.identity_service.controller.dto;

import com.example.identity_service.service.oauth2.ExternalIdentity;

/**
 * What the SPA needs to word the confirmation page. The identity itself stays in the HttpOnly cookie: the
 * page can say which account is waiting, but cannot change it.
 */
public record PendingLinkResponse(String provider, String email) {

    public static PendingLinkResponse from(ExternalIdentity identity) {
        return new PendingLinkResponse(identity.provider().name(), identity.email());
    }
}
