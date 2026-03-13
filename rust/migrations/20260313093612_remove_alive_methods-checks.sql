DROP TABLE alive_methods;
 
CREATE TABLE alive_methods (
    id INTEGER,
    method TEXT DEFAULT 'icmp',
    PRIMARY KEY (id, method),
    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);
