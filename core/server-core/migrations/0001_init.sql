-- Reference schema for the four Host SPI stores. PROPOSED: the database schema is a
-- stop-and-ask choice (build prompt rule 0.2), and this has not been approved yet.
--
-- server-core exchanges each record as a JSON document and owns its fields, so a host
-- keeps the document as it is and only adds the columns it has to query by. Every host
-- applies this with its own migration tool.

CREATE TABLE qalqon_users (
    user_id  TEXT PRIMARY KEY,
    record   TEXT NOT NULL
);

CREATE TABLE qalqon_devices (
    device_id TEXT PRIMARY KEY,
    user_id   TEXT NOT NULL,
    record    TEXT NOT NULL
);
CREATE INDEX qalqon_devices_user ON qalqon_devices (user_id);

CREATE TABLE qalqon_policies (
    name    TEXT PRIMARY KEY,
    record  TEXT NOT NULL
);

-- Append-only. A host must not offer update or delete on this table.
CREATE TABLE qalqon_audit (
    seq     BIGINT PRIMARY KEY,
    at      BIGINT NOT NULL,
    record  TEXT NOT NULL
);
