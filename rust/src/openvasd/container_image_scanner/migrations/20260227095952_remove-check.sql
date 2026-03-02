-- Removes DB check to prepare for turso enablement

PRAGMA foreign_keys = OFF;

--------------------------------------------------------------------------------
-- SCANS: preserve (id, status), rebuild table without status, add status back
--------------------------------------------------------------------------------

DROP TRIGGER IF EXISTS "trg_update_scans_host_on_insert";
DROP TRIGGER IF EXISTS "trg_update_scans_host_counters";
-- 1) Save current scan statuses
CREATE TEMP TABLE _scans_status_tmp (
  id     INTEGER NOT NULL PRIMARY KEY,
  status TEXT
);

INSERT INTO _scans_status_tmp (id, status)
SELECT id, status
FROM scans;

-- 2) Recreate scans without status (this removes the CHECK by removing the column)
CREATE TABLE scans__no_status (
  id INTEGER PRIMARY KEY,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  start_time INTEGER DEFAULT 0,
  end_time INTEGER DEFAULT 0,

  host_all INTEGER DEFAULT 0,
  host_excluded INTEGER DEFAULT 0,
  host_dead INTEGER DEFAULT 0,
  host_alive INTEGER DEFAULT 0,
  host_queued INTEGER DEFAULT 0,
  host_finished INTEGER DEFAULT 0,

  FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);

INSERT INTO scans__no_status (
  id, created_at, start_time, end_time,
  host_all, host_excluded, host_dead, host_alive, host_queued, host_finished
)
SELECT
  id, created_at, start_time, end_time,
  host_all, host_excluded, host_dead, host_alive, host_queued, host_finished
FROM scans;

DROP TABLE scans;
ALTER TABLE scans__no_status RENAME TO scans;

-- 3) Add status back without CHECK (keep same default)
ALTER TABLE scans
ADD COLUMN status TEXT DEFAULT 'stored';

-- 4) Restore scan statuses
UPDATE scans
SET status = (SELECT t.status FROM _scans_status_tmp t WHERE t.id = scans.id);

DROP TABLE _scans_status_tmp;

--------------------------------------------------------------------------------
-- IMAGES: preserve (id, image, status), rebuild table without status, add back
--------------------------------------------------------------------------------

-- 5) Save current image statuses
CREATE TEMP TABLE _images_status_tmp (
  id     INTEGER NOT NULL,
  image  TEXT    NOT NULL,
  status TEXT,
  PRIMARY KEY (id, image)
);

INSERT INTO _images_status_tmp (id, image, status)
SELECT id, image, status
FROM images;

-- 6) Recreate images without status
CREATE TABLE images__no_status (
  id    INTEGER NOT NULL,
  image TEXT    NOT NULL,
  PRIMARY KEY (id, image),
  FOREIGN KEY (id) REFERENCES scans(id) ON DELETE CASCADE
);

INSERT INTO images__no_status (id, image)
SELECT id, image
FROM images;

DROP TABLE images;
ALTER TABLE images__no_status RENAME TO images;

-- 7) Add status back without CHECK (keep same default)
ALTER TABLE images
ADD COLUMN status TEXT DEFAULT 'pending';

-- 8) Restore image statuses
UPDATE images
SET status = (
  SELECT t.status
  FROM _images_status_tmp t
  WHERE t.id = images.id AND t.image = images.image
);


CREATE INDEX idx_scanning_images_scan_status ON images(id, status);

DROP TABLE _images_status_tmp;

DROP TABLE timed_layer;
CREATE TABLE timed_layer(
    layer_index INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    image TEXT NOT NULL,
    kind TEXT NOT NULL,
    micro_seconds INTEGER, 
    PRIMARY KEY (layer_index, scan_id, image, kind),
    FOREIGN KEY (scan_id, image) REFERENCES images(id, image) ON DELETE CASCADE
);


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
