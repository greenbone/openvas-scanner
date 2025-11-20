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
    start_time INTEGER DEFAULT 0,
    end_time INTEGER DEFAULT 0,
    status TEXT DEFAULT 'stored' CHECK(status IN ('stored', 'requested', 'running', 'stopped', 'failed', 'succeeded')),

    host_all INTEGER DEFAULT 0,
    host_excluded INTEGER DEFAULT 0,
    host_dead INTEGER DEFAULT 0,
    host_alive INTEGER DEFAULT 0,
    host_queued INTEGER DEFAULT 0,
    host_finished INTEGER DEFAULT 0,
    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);

CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at);

CREATE TABLE registry (
    id INTEGER,
    host TEXT,
    PRIMARY KEY (id, host),
    FOREIGN KEY (id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE credentials (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,
    FOREIGN KEY (id) REFERENCES scans(id) ON DELETE CASCADE
);

-- stores currently running images, when an image is scanned it needs to be removed here
CREATE TABLE images (
    id INTEGER,
    image TEXT,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'scanning', 'stopped', 'failed', 'succeeded', 'excluded')),
    PRIMARY KEY (id, image),
    FOREIGN KEY (id) REFERENCES scans(id) ON DELETE CASCADE
);


CREATE INDEX idx_scanning_images_scan_status ON images(id, status);

CREATE TABLE results (
    scan_id INTEGER,
    id INTEGER,
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
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);


CREATE TABLE preferences (
    id INTEGER,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (id, key),
    FOREIGN KEY (id) REFERENCES scans(id) ON DELETE CASCADE
);

-- add new trigger to keep track of status changes.
-- this is done here to change the scan status and keep track of the hosts counter 
-- immediately

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

