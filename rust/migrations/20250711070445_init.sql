CREATE TABLE client_scan_map (
    id INTEGER PRIMARY KEY,
    client_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    UNIQUE (client_id, scan_id)
);

CREATE INDEX idx_client_scan_map ON client_scan_map(scan_id, client_id);

CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    start_time INTEGER,
    end_time INTEGER,
    -- we have to store them instead of calculating them via resolved_host 
    -- because in the case of OSPD we don't know which hosts are resolved and in which state they are in
    host_dead INTEGER NOT NULL DEFAULT 0,
    host_alive INTEGER NOT NULL DEFAULT 0,
    host_queued INTEGER NOT NULL DEFAULT 0,
    host_excluded INTEGER NOT NULL DEFAULT 0,
    host_all INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'stored' CHECK(status IN ('stored', 'requested', 'running', 'stopped', 'failed', 'succeeded')),
    auth_data TEXT NOT NULL, -- blob that is interpret by the application, containing the whole credentials

    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);

CREATE TRIGGER trg_update_scans_start_time
AFTER UPDATE OF status ON scans
FOR EACH ROW
WHEN NEW.status = 'running' AND OLD.status IS NOT 'running'
BEGIN
    UPDATE scans
    SET start_time = CAST(strftime('%s', 'now') AS INTEGER), 
        end_time = NULL
    WHERE id = NEW.id;
END;

CREATE TRIGGER trg_update_scans_end_time
AFTER UPDATE OF status ON scans
FOR EACH ROW
WHEN (NEW.status = 'failed' OR NEW.status = 'succeeded' OR NEW.status = 'stopped' ) AND OLD.status IS NOT NEW.status
BEGIN
    UPDATE scans
    SET end_time = CAST(strftime('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;



CREATE INDEX idx_scans_status ON scans(status);

CREATE TABLE preferences (
    id INTEGER,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (id, key),
    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);


CREATE TABLE ports (
    id INTEGER,
    protocol TEXT DEFAULT 'udp_tcp' CHECK(protocol IN ('udp_tcp', 'udp', 'tcp')),
    start int NOT NULL,
    end int CHECK (end IS NULL OR start <= end),
    alive BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (id, protocol, start, alive, end),
    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);
CREATE INDEX idx_ports_alive ON ports(id, alive);

CREATE TABLE alive_methods (
    id INTEGER,
    method TEXT NOT NULL CHECK(method IN ('icmp', 'tcp_syn', 'tcp_ack', 'arp', 'consider_alive' )),
    PRIMARY KEY (id, method),
    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);

CREATE TABLE hosts (
    id INTEGER,
    host TEXT NOT NULL,
    PRIMARY KEY (id, host),
    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);

CREATE TABLE vts (
    id INTEGER,
    vt TEXT NOT NULL,
    PRIMARY KEY (id, vt),
    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);

CREATE TABLE vt_parameters (
    id INTEGER,
    vt TEXT NOT NULL,
    param_id int NOT NULL,
    param_value TEXT,
    PRIMARY KEY (id, vt, param_id),
    FOREIGN KEY (id, vt) REFERENCES vts(id, vt) ON DELETE CASCADE
);

-- maybe just store the json as a blob as we just get the data for id and result_id but never actually work with the data
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
    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);

CREATE TABLE feed (
    hash TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    type TEXT NOT NULL CHECK(type in ('advisories', 'nasl')) PRIMARY KEY
);

CREATE TABLE plugins (
    oid TEXT PRIMARY KEY,
    feed_type TEXT NOT NULL,
    -- we store the plugin as a json blob otherwise we would need to have 8 tables
    -- as we just need the information when we start a script it is simpler to fetch
    -- and then deserialize that blob into a struct than having to fetch data from multiple
    -- tables.
    --
    -- While unusual it is also faster when we just want to dump all nvts on e.g. /vts?information=true
    json_blob BLOB NOT NULL,
    FOREIGN KEY (feed_type) REFERENCES feed (type) ON DELETE CASCADE
);

-- Maybe move scripts to own sqlite pool so that they don't interfere?
--- Contains host information that are already resolved. 
-- This this differentation is necessary because a scan can contain:
-- - ip ranges
-- - dns entries
-- - oci images
CREATE TABLE resolved_hosts (
    id INTEGER,
    original_host TEXT NOT NULL,
    resolved_host TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('oci', 'ipv4', 'ipv6', 'dns')),
    scan_status TEXT NOT NULL DEFAULT 'queued' CHECK(scan_status IN ('queued', 'scanning', 'stopped', 'failed', 'succeeded', 'excluded')),
    host_status TEXT NOT NULL DEFAULT 'unknown' CHECK(host_status IN ('alive', 'dead', 'unknown')),
    PRIMARY KEY (id, resolved_host),
    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);

CREATE INDEX idx_resolved_hosts_host_status_scan_status_kind ON resolved_hosts(id, host_status, scan_status, kind);

CREATE TABLE knowledge_base_items(
    id INTEGER PRIMARY KEY,
    client_scan_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    FOREIGN KEY (client_scan_id, host) REFERENCES resolved_hosts(id, resolved_host)
);

CREATE INDEX idx_knowledge_base_items ON knowledge_base_items(id, host, key);


