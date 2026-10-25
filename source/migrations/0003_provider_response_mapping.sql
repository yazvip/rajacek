-- Product-aware JSON response mapping for administrator-managed providers.

ALTER TABLE third_party_endpoints
    ADD COLUMN response_mapping JSON NULL AFTER active;

UPDATE third_party_endpoints
SET response_mapping = JSON_OBJECT(
    'status_path', 'status',
    'valid_values', JSON_ARRAY('valid', 'success', 'registered'),
    'invalid_values', JSON_ARRAY('invalid', 'unregistered'),
    'not_found_values', JSON_ARRAY('not_found', 'not found'),
    'pending_values', JSON_ARRAY('pending', 'processing'),
    'message_path', 'message',
    'account_name_path', IF(product_code = 'bank_account', 'result.account_name', NULL),
    'provider_path', 'result.provider',
    'registered_path', IF(product_code = 'bank_account', NULL, 'result.registered'),
    'reference_path', 'result.reference'
)
WHERE response_mapping IS NULL;

ALTER TABLE third_party_endpoints
    MODIFY COLUMN response_mapping JSON NOT NULL;
