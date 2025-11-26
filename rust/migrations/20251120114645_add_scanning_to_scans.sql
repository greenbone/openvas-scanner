-- Adds new table for scanning host progress
CREATE TABLE host_scanning (
    id INTEGER NOT NULL,
    host_ip TEXT NOT NULL,
    progress INTEGER NOT NULL,
    PRIMARY KEY (id, host_ip),
    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);
