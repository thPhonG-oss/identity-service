package com.example.identity_service.service.oauth2;

import com.example.identity_service.model.User;

/**
 * How a login with an external provider turned out.
 *
 * @param status what happened
 * @param user   the user to sign in; {@code null} when the status is LINK_REQUIRED
 */
public record ExternalLoginResult(Status status, User user) {

    public enum Status {
        /** This provider account was linked to a user before: sign that user in. */
        SIGNED_IN,
        /** The email was not known: a new user (without a password) was created and linked. */
        ACCOUNT_CREATED,
        /** The email belongs to a user who never linked this provider account: nothing was changed, the
         *  owner of that user must first prove it by its password. */
        LINK_REQUIRED
    }

    static ExternalLoginResult linkRequired() {
        return new ExternalLoginResult(Status.LINK_REQUIRED, null);
    }
}
