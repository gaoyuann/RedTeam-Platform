-- Source scan schema, version 1. The application executes this migration transactionally.
CREATE TABLE tasks(
    id TEXT PRIMARY KEY NOT NULL,
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE files(
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    original_path TEXT NOT NULL,
    content TEXT NOT NULL,
    PRIMARY KEY(task_id, path)
);

CREATE TABLE findings(
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    finding_key TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY(task_id, finding_key)
);

CREATE TABLE responses(
    id INTEGER PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    raw TEXT NOT NULL,
    parsed TEXT NOT NULL
);
