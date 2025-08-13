-- Contains the table use by the scan runtime directly.
-- 
-- It is not used ;by openvasd but by scannerlib within storage/sqlite
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
);


CREATE TABLE resolved_hosts (
    id INTEGER,
    original_host TEXT NOT NULL,
    resolved_host TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('oci', 'ipv4', 'ipv6', 'dns')),
    scan_status TEXT NOT NULL DEFAULT 'queued' CHECK(scan_status IN ('queued', 'scanning', 'stopped', 'failed', 'succeeded', 'excluded')),
    host_status TEXT NOT NULL DEFAULT 'unknown' CHECK(host_status IN ('alive', 'dead', 'unknown')),
    PRIMARY KEY (id, resolved_host),
    FOREIGN KEY (id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX idx_resolved_hosts_host_status_scan_status_kind ON resolved_hosts(id, host_status, scan_status, kind);

CREATE TABLE knowledge_base_items(
    id INTEGER PRIMARY KEY,
    client_scan_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    key BLOB NOT NULL,
    json_blob BLOB NOT NULL,
    FOREIGN KEY (client_scan_id, host) REFERENCES resolved_hosts(id, resolved_host) ON DELETE CASCADE
);

CREATE INDEX idx_knowledge_base_items ON knowledge_base_items(host, key);

CREATE TABLE results (
    id INTEGER,
    result_id INTEGER NOT NULL,
    type TEXT,
    ip_address TEXT,
    hostname TEXT,
    oid TEXT,
    port INTEGER,
    protocol TEXT,
    message TEXT,
    detail_name TEXT,
    detail_value TEXT,
    source_type TEXT,
    source_name TEXT,
    source_description TEXT,
    PRIMARY KEY (id, result_id),
    FOREIGN KEY (id) REFERENCES scans(id) ON DELETE CASCADE
);

