-- Add migration script here
ALTER TABLE scans ADD COLUMN host_scanning TEXT NOT NULL DEFAULT '';
