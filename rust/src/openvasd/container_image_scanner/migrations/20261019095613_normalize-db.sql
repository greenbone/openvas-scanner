-- no-transaction
-- WARNING: don't delete the first line. It is a special directive for sqlx.
-- sqlx wraps every migration in a transaction which invalidates PRAGMA foreign_keys off which then
-- triggers CASCADE on delete during the migration.
-- The first line tells sqlx not to start a transaction, we do it manually after the PRAGMA instead.
PRAGMA foreign_keys = OFF;

BEGIN;

CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);

DROP TRIGGER trg_update_scans_host_on_insert;
DROP TRIGGER trg_update_scans_host_counters;

CREATE TABLE scans_new (
    id INTEGER PRIMARY KEY,
    scan_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    start_time INTEGER DEFAULT 0,
    end_time INTEGER DEFAULT 0,
    host_dead INTEGER DEFAULT 0,
    host_alive INTEGER DEFAULT 0,
    host_queued INTEGER DEFAULT 0,
    host_excluded INTEGER DEFAULT 0,
    host_all INTEGER DEFAULT 0,
    host_finished INTEGER DEFAULT 0,
    status TEXT DEFAULT 'stored',
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
    '0 MDAwMDAwMDAwMDAw ' || CASE
        WHEN c.id IS NULL OR c.username IS NULL THEN '[]'
        ELSE json_array(json_object(
            'up', json_object(
                'username', c.username,
                'password', coalesce(c.password, '')
            ),
            'service', 'generic'
        ))
    END
FROM scans s
JOIN client_scan_map cm ON s.id = cm.id
LEFT JOIN credentials c ON s.id = c.id;

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

CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at);

COMMIT;
PRAGMA foreign_keys = ON;
