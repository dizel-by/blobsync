CREATE TABLE IF NOT EXISTS bsfiles (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(4096) NOT NULL,
    filename_sha256 CHAR(64) GENERATED ALWAYS AS (SHA2(filename, 256)) STORED,
    size BIGINT NOT NULL,
    sha256 CHAR(64) NOT NULL,
    dateadded DATETIME NOT NULL,
    datedeleted DATETIME DEFAULT NULL,
    UNIQUE KEY uq_bsfiles_filename_sha256 (filename_sha256)
);

CREATE TABLE IF NOT EXISTS bsevents (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    node VARCHAR(255) NOT NULL,
    eventtype ENUM('add', 'remove') NOT NULL,
    fileid BIGINT NOT NULL,
    dateadded DATETIME NOT NULL,
    KEY idx_bsevents_dateadded (dateadded),
    KEY idx_bsevents_fileid (fileid),
    CONSTRAINT fk_bsevents_fileid FOREIGN KEY (fileid) REFERENCES bsfiles(id)
);

CREATE TABLE IF NOT EXISTS bsnodes (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    node VARCHAR(255) NOT NULL,
    address VARCHAR(512) NOT NULL,
    lasteventid BIGINT NOT NULL DEFAULT 0,
    aclsha256 CHAR(64) NOT NULL DEFAULT '',
    lastseen DATETIME NOT NULL,
    UNIQUE KEY uq_bsnodes_node (node),
    KEY idx_bsnodes_lastseen (lastseen)
);
