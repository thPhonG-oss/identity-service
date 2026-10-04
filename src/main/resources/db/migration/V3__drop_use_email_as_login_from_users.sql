-- Login is by email only, so the per-user flag added in V2 is no longer needed.
ALTER TABLE users DROP COLUMN use_email_as_login;
