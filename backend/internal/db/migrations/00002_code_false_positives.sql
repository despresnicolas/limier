-- +goose Up
-- Code findings the user marked as false positives: later code scans of the project leave them out.
-- Matched on rule, file and detail (never the line, so moving code keeps the mark). The detail of a
-- secret is already masked; a per-file count (console-log, ts-any) is stored as '' so the mark holds.
CREATE TABLE code_false_positives (
    project_id  INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    rule        TEXT NOT NULL,
    file        TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f+00:00', 'now')),
    PRIMARY KEY (project_id, rule, file, detail)
);

-- +goose Down
DROP TABLE code_false_positives;
