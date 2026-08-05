CREATE INDEX idx_plugins_filename ON plugins (json_extract(json_blob, '$.filename'));
