package com.example.identity_service.service.oauth2;

import com.example.identity_service.model.AuthProvider;

/**
 * Who an external provider says the user is, after its ID token passed every check.
 *
 * There is no "email verified" flag on purpose: a token whose email is not verified is rejected before
 * this object is built, so an ExternalIdentity always carries an email the provider vouches for.
 *
 * @param provider the provider that issued the token
 * @param subject  the provider's stable id of the account (the "sub" claim). It never changes, unlike the
 *                 email, so it is what links a later sign-in to the same user.
 * @param email    the verified email of the account
 */
public record ExternalIdentity(AuthProvider provider, String subject, String email) {
}
