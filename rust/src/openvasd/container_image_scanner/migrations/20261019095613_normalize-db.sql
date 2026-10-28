-- temporarily disable foreign key constraints
PRAGMA foreign_keys = OFF;

CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);

DROP TRIGGER trg_update_scans_host_on_insert;
DROP TRIGGER trg_update_scans_host_counters;

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
    host_finished INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'stored' CHECK(status IN ('stored', 'requested', 'running', 'stopped', 'failed', 'succeeded')),
    auth_data TEXT NOT NULL,
    UNIQUE (client_id, scan_id)
);

-- Migrate the data between the tables
INSERT INTO scans_new (
    id, client_id, scan_id, created_at, start_time, end_time,
    host_dead, host_alive, host_queued, host_excluded, host_all, host_finished, status, auth_data
)
SELECT
    s.id, cm.client_id, cm.scan_id, s.created_at, s.start_time, s.end_time,
    s.host_dead, s.host_alive, s.host_queued, s.host_excluded, s.host_all, s.host_finished, s.status,
    '0 MDAwMDAwMDAwMDAw [{ "up": { "username": "' || c.username || '", "password": "' || c.password || '" }, "service": "generic" }]'
FROM scans s
JOIN client_scan_map cm ON s.id = cm.id
JOIN credentials c ON s.id = c.id;


DROP TABLE credentials;
DROP TABLE client_scan_map;
DROP TABLE scans;

ALTER TABLE scans_new RENAME TO scans;

CREATE TRIGGER trg_update_scans_host_on_insert
AFTER INSERT ON images
BEGIN
    UPDATE scans
    SET host_queued = host_queued + CASE WHEN NEW.status = 'pending' THEN 1 ELSE 0 END,
        host_excluded = host_excluded + CASE WHEN NEW.status = 'excluded' THEN 1 ELSE 0 END,
        host_finished = host_finished + CASE WHEN NEW.status = 'excluded' THEN 1 ELSE 0 END
    WHERE id = NEW.id;
END;

CREATE TRIGGER trg_update_scans_host_counters
AFTER UPDATE OF status ON images
FOR EACH ROW
WHEN OLD.status != NEW.status AND (NEW.status = 'failed' OR NEW.status = 'succeeded')
BEGIN
    UPDATE scans
    SET host_dead = host_dead + CASE WHEN NEW.status = 'failed' THEN 1 ELSE 0 END,
        host_alive = host_alive + CASE WHEN NEW.status = 'succeeded' THEN 1 ELSE 0 END,
        host_finished = host_finished + 1,
        host_queued = host_queued - 1
    WHERE id = OLD.id;
END;

PRAGMA foreign_keys = ON;
