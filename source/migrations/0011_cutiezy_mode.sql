-- The Cutiezy request mode joins the endpoint mode enum.
ALTER TABLE third_party_endpoints
    MODIFY request_mode ENUM('generic', 'tukangcek', 'cutiezy') NOT NULL DEFAULT 'generic';
