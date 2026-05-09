const fs = require('fs');
const child_process = require('child_process');

const token = "demo_token_123456789";

function findUser(req, db) {
  const sql = `SELECT * FROM users WHERE name = '${req.query.name}'`;
  return db.query(sql);
}

function render(req, el) {
  el.innerHTML = req.query.html;
}

function archive(req) {
  child_process.exec("tar czf /tmp/" + req.query.name + ".tgz ./data");
}

function read(req, res) {
  fs.readFile('/srv/app/uploads/' + req.query.file, (err, data) => res.end(data));
}

var debug = true;
if (debug == true) {
  console.log('debug enabled');
}
