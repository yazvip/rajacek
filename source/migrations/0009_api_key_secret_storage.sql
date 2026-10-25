-- Recoverable API-key storage: AES-256-GCM ciphertext of the full key so
-- the owning member (portal) and admins (panel) can view a key again.
-- NULL for keys issued before this feature (hash-only, not revealable).
ALTER TABLE admin_api_keys ADD COLUMN secret_ciphertext BLOB NULL AFTER secret_hash;
