-- Refresh tokens are opaque random strings. Only their SHA-256 hash is stored, so a leaked database
-- cannot be used to refresh anyone's session (same idea as storing password hashes).
--
-- family_id groups every token that descends from one login. Each use of a token rotates it: it is marked
-- revoked and a new token is issued in the same family. If an already-used token shows up again, someone
-- is replaying a stolen copy and the whole family is revoked.
CREATE TABLE refresh_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id  UUID        NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX uq_refresh_tokens_token_hash ON refresh_tokens (token_hash);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens (family_id);
