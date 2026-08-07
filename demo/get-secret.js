// Demo: a 3rd-party node app reads the secret the theta-agent rendered to disk.
const fs = require('fs');
const path = '/etc/theta/rendered/db.env';
console.log('=== node app reads the rendered secret ===');
if (fs.existsSync(path)) {
  const env = fs.readFileSync(path, 'utf8');
  const db = {};
  for (const line of env.split('\n')) {
    const m = /^(\w+)="(.*)"$/.exec(line.trim());
    if (m) db[m[1]] = m[2];
  }
  console.log('DB_USER=' + db.DB_USER);
  console.log('DB_PASS=' + db.DB_PASS);
} else {
  console.error('rendered secret not found — run render_secrets first');
  process.exit(1);
}
