-- name: AddCodeFalsePositive :exec
INSERT INTO code_false_positives (project_id, rule, file, detail) VALUES (?, ?, ?, ?)
ON CONFLICT DO NOTHING;

-- name: DeleteCodeFalsePositive :exec
DELETE FROM code_false_positives WHERE project_id = ? AND rule = ? AND file = ? AND detail = ?;

-- name: ListCodeFalsePositives :many
SELECT * FROM code_false_positives WHERE project_id = ? ORDER BY created_at;
