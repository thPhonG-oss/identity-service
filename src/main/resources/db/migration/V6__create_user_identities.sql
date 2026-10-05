-- A user who signs in only with an external provider (Google, ...) has no password.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- Which account of an external provider belongs to which user.
-- provider_user_id is the provider's stable id for the account (the "sub" claim of a Google ID token).
-- It never changes, unlike the email, so it is what a later sign-in is matched on.
CREATE TABLE user_identities (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider         VARCHAR(20)  NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    email            VARCHAR(255) NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- One account of a provider can belong to only one user...
CREATE UNIQUE INDEX uq_user_identities_provider_subject ON user_identities (provider, provider_user_id);
-- ...and a user can link at most one account of each provider.
CREATE UNIQUE INDEX uq_user_identities_user_provider ON user_identities (user_id, provider);
