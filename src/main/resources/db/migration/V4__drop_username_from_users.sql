-- Users are identified and log in by email only. Dropping the column also drops its unique
-- index uq_users_username_lower, because that index covers only this column.
ALTER TABLE users DROP COLUMN username;
