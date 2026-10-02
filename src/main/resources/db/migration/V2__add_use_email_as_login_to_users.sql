-- NOT NULL + DEFAULT keeps this safe for rows that already exist.
ALTER TABLE users ADD COLUMN use_email_as_login BOOLEAN NOT NULL DEFAULT FALSE;
