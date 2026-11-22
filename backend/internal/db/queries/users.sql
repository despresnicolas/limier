-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ?;

-- name: CreateUser :one
INSERT INTO users (email, name) VALUES (?, ?)
ON CONFLICT (email) DO UPDATE SET name = excluded.name
RETURNING *;
