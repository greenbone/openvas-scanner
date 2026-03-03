-- Formalizes the name of the fields across container_image_scanner and nasl
ALTER TABLE results RENAME COLUMN id TO scan_id;
ALTER TABLE results RENAME COLUMN result_id TO id;

