-- Generic endpoints can use GET (query params) in addition to POST JSON.
-- http_method only applies to request_mode='generic'; Tukangcek and Cutiezy
-- keep their fixed dispatch. code_param/number_param name the query params
-- for the service code and the account number; key_param (NULL = unset)
-- additionally appends the API key as a query param.
ALTER TABLE third_party_endpoints
    ADD COLUMN http_method VARCHAR(8) NOT NULL DEFAULT 'POST',
    ADD COLUMN code_param VARCHAR(80) NOT NULL DEFAULT 'code',
    ADD COLUMN number_param VARCHAR(80) NOT NULL DEFAULT 'target',
    ADD COLUMN key_param VARCHAR(80) NULL;
