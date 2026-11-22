const { exec } = require('child_process');
const fs = require('fs');

// exec('rm -rf ' + req.query.dir) in a comment must not match
app.get('/run', (req, res) => {
  exec('ls ' + req.query.dir, () => {});
  exec('ls -la', () => {});
  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
  fs.readFile(req.query.file, () => {});
  res.redirect(req.query.next);
});
