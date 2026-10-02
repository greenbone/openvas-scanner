-- Stores the sha256 hashsum and mtime of the .nasl/.inc file
ALTER TABLE plugins ADD COLUMN hashsum TEXT NOT NULL DEFAULT '';
ALTER TABLE plugins ADD COLUMN mtime TEXT NOT NULL DEFAULT '';
