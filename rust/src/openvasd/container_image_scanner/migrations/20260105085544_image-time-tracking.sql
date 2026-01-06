-- Is used to track the micro seconds it took to download and extract each layer


CREATE TABLE timed_layer(
    layer_index INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    image TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('download', 'extraction')),
    micro_seconds INTEGER, 
    PRIMARY KEY (layer_index, scan_id, image, kind),
    FOREIGN KEY (scan_id, image) REFERENCES images(id, image) ON DELETE CASCADE
);

