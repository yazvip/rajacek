-- Runtime-tunable settings managed from the admin panel (e.g. provider guard
-- numbers). Environment variables seed the defaults; rows here win when present.
CREATE TABLE runtime_settings (
    setting_key VARCHAR(120) NOT NULL PRIMARY KEY,
    setting_value VARCHAR(255) NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
