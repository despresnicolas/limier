-- name: GetAppSettings :one
SELECT * FROM app_settings;

-- name: SetWatchVulns :exec
UPDATE app_settings SET watch_vulns = ?;
