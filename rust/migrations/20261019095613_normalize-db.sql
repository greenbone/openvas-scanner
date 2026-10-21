-- temporarily disable foreign key constraints
PRAGMA foreign_keys = OFF;

CREATE TABLE scans_new (
    id INTEGER PRIMARY KEY,
    scan_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    start_time INTEGER,
    end_time INTEGER,
    host_dead INTEGER NOT NULL DEFAULT 0,
    host_alive INTEGER NOT NULL DEFAULT 0,
    host_queued INTEGER NOT NULL DEFAULT 0,
    host_excluded INTEGER NOT NULL DEFAULT 0,
    host_all INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'stored' CHECK(status IN ('stored', 'requested', 'running', 'stopped', 'failed', 'succeeded')),
    auth_data TEXT NOT NULL,
    UNIQUE (client_id, scan_id)
);

CREATE TABLE preferences_new (
    id INTEGER,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (id, key),
    FOREIGN KEY (id) REFERENCES scans_new(id) ON DELETE CASCADE
);

CREATE TABLE ports_new (
    id INTEGER,
    protocol TEXT DEFAULT 'udp_tcp' CHECK(protocol IN ('udp_tcp', 'udp', 'tcp')),
    start int NOT NULL,
    end int CHECK (end IS NULL OR start <= end),
    alive BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (id, protocol, start, alive, end),
    FOREIGN KEY (id) REFERENCES scans_new(id) ON DELETE CASCADE
);


CREATE TABLE alive_methods_new (
    id INTEGER,
    method TEXT DEFAULT 'icmp',
    PRIMARY KEY (id, method),
    FOREIGN KEY (id) REFERENCES scans_new(id) ON DELETE CASCADE
);

CREATE TABLE hosts_new (
    id INTEGER,
    host TEXT NOT NULL,
    PRIMARY KEY (id, host),
    FOREIGN KEY (id) REFERENCES scans_new(id) ON DELETE CASCADE
);

CREATE TABLE host_scanning_new (
    id INTEGER NOT NULL,
    host_ip TEXT NOT NULL,
    progress INTEGER NOT NULL,
    PRIMARY KEY (id, host_ip),
    FOREIGN KEY (id) REFERENCES scans_new(id) ON DELETE CASCADE
);

CREATE TABLE vts_new (
    id INTEGER,
    vt TEXT NOT NULL,
    PRIMARY KEY (id, vt),
    FOREIGN KEY (id) REFERENCES scans_new(id) ON DELETE CASCADE
);

CREATE TABLE vt_parameters_new (
    id INTEGER,
    vt TEXT NOT NULL,
    param_id int NOT NULL,
    param_value TEXT,
    PRIMARY KEY (id, vt, param_id),
    FOREIGN KEY (id, vt) REFERENCES vts_new(id, vt) ON DELETE CASCADE
);

CREATE TABLE results_new (
    id INTEGER NOT NULL,
    scan_id INTEGER,
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
    PRIMARY KEY (scan_id, id),
    FOREIGN KEY (scan_id) REFERENCES scans_new(id) ON DELETE CASCADE
);

CREATE TABLE resolved_hosts_new (
    id INTEGER,
    original_host TEXT NOT NULL,
    resolved_host TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('oci', 'ipv4', 'ipv6', 'dns')),
    scan_status TEXT NOT NULL DEFAULT 'queued' CHECK(scan_status IN ('queued', 'scanning', 'stopped', 'failed', 'succeeded', 'excluded')),
    host_status TEXT NOT NULL DEFAULT 'unknown' CHECK(host_status IN ('alive', 'dead', 'unknown')),
    PRIMARY KEY (id, resolved_host),
    FOREIGN KEY (id) REFERENCES scans_new(id) ON DELETE CASCADE
);

CREATE TABLE knowledge_base_items_new (
    id INTEGER PRIMARY KEY,
    client_scan_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    FOREIGN KEY (client_scan_id, host) REFERENCES resolved_hosts_new(id, resolved_host)
);

-- Migrate the data between the tables
INSERT INTO scans_new (
    id, client_id, scan_id, created_at, start_time, end_time,
    host_dead, host_alive, host_queued, host_excluded, host_all, status, auth_data
)
SELECT
    s.id, c.client_id, c.scan_id, s.created_at, s.start_time, s.end_time,
    s.host_dead, s.host_alive, s.host_queued, s.host_excluded, s.host_all, s.status, s.auth_data
FROM scans s
JOIN client_scan_map c ON s.id = c.id;

INSERT INTO preferences_new SELECT * FROM preferences;
INSERT INTO ports_new SELECT * FROM ports;
INSERT INTO alive_methods_new SELECT * FROM alive_methods;
INSERT INTO hosts_new SELECT * FROM hosts;
INSERT INTO vts_new SELECT * FROM vts;
INSERT INTO vt_parameters_new SELECT * FROM vt_parameters;
INSERT INTO results_new SELECT * FROM results;
INSERT INTO resolved_hosts_new SELECT * FROM resolved_hosts;

-- Remove the old tables
DROP TABLE knowledge_base_items;
DROP TABLE resolved_hosts;
DROP TABLE results;
DROP TABLE vt_parameters;
DROP TABLE vts;
DROP TABLE hosts;
DROP TABLE alive_methods;
DROP TABLE ports;
DROP TABLE preferences;
DROP TABLE scans;
DROP TABLE client_scan_map;

-- Reassign their original names
ALTER TABLE scans_new RENAME TO scans;
ALTER TABLE preferences_new RENAME TO preferences;
ALTER TABLE ports_new RENAME TO ports;
ALTER TABLE alive_methods_new RENAME TO alive_methods;
ALTER TABLE hosts_new RENAME TO hosts;
ALTER TABLE vts_new RENAME TO vts;
ALTER TABLE vt_parameters_new RENAME TO vt_parameters;
ALTER TABLE results_new RENAME TO results;
ALTER TABLE resolved_hosts_new RENAME TO resolved_hosts;
ALTER TABLE knowledge_base_items_new RENAME TO knowledge_base_items;

CREATE INDEX idx_ports_alive ON ports(id, alive);
CREATE INDEX idx_resolved_hosts_host_status_scan_status_kind ON resolved_hosts(id, host_status, scan_status, kind);
CREATE INDEX idx_knowledge_base_items ON knowledge_base_items(id, host, key);

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

PRAGMA foreign_keys = ON;
