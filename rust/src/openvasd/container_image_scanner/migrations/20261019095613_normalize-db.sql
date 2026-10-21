CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);

ALTER TABLE scans ADD auth_data TEXT;
UPDATE scans SET auth_data = '0 MDAwMDAwMDAwMDAw [{ "up": { "username": "' || c.username || '", "password": "' || c.password || '" }, "service": "generic" }]' FROM credentials c WHERE c.id = scans.id;
DROP TABLE credentials;
