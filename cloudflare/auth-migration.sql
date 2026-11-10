-- Run once in Cloudflare D1 Console before enabling parent login.
CREATE TABLE IF NOT EXISTS auth_attempts (
  bucket TEXT PRIMARY KEY,
  failures INTEGER NOT NULL DEFAULT 0,
  reset_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_reset ON auth_attempts(reset_at);
