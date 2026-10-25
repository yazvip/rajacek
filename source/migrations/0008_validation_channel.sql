-- Fase 2 (member sandbox): record where each validation came from —
-- the public API ('api') or the member portal's live-check sandbox
-- ('portal'). Existing rows default to 'api'.

ALTER TABLE validation_requests
    ADD COLUMN channel VARCHAR(16) NOT NULL DEFAULT 'api';
