-- Multiple third-party servers per product: the bank service (and any other
-- product) may run several endpoints at once and race them. The old
-- one-row-per-product uniqueness goes away; rows are keyed by id.
ALTER TABLE third_party_endpoints DROP INDEX uq_third_party_endpoints_product;
ALTER TABLE third_party_endpoints ADD KEY idx_third_party_endpoints_product (product_code);
