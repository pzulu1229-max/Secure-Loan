// verify_chain.js (Member 4)
// Recomputes every hash in audit_log and checks each row links to the one before it.
// Usage: npm install mysql2 dotenv   then   node verify_chain.js
// .env: DB_HOST=localhost  DB_NAME=secureloan  AUDITOR_USER=auditor  AUDITOR_PASS=...

require('dotenv').config();
const crypto = require('crypto');
const mysql = require('mysql2/promise');

const GENESIS = '0'.repeat(64);

// Must match the CONCAT_WS in the write_audit procedure exactly.
function computeHash(r, previousHash) {
  const s = (v) => (v === null || v === undefined ? '' : String(v));
  const payload = [
    previousHash,
    r.db_user,
    r.action,
    s(r.loan_id),
    s(r.old_value),
    s(r.new_value),
    r.changed_at, // 'YYYY-MM-DD HH:MM:SS' because dateStrings is true
  ].join('|');
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

async function main() {
  // Connect as the auditor: the only account allowed to read audit_log besides root.
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'secureloan',
    user: process.env.AUDITOR_USER || 'auditor',
    password: process.env.AUDITOR_PASS,
    dateStrings: true,
  });

  const [rows] = await conn.execute('SELECT * FROM audit_log ORDER BY log_id ASC');
  await conn.end();

  let expectedPrev = GENESIS;
  for (const row of rows) {
    if (row.previous_hash !== expectedPrev) {
      console.log(`TAMPERING DETECTED at log_id ${row.log_id}: chain link broken (a row was changed, removed or inserted before it).`);
      process.exit(1);
    }
    if (computeHash(row, row.previous_hash) !== row.current_hash) {
      console.log(`TAMPERING DETECTED at log_id ${row.log_id}: row contents do not match its hash.`);
      process.exit(1);
    }
    expectedPrev = row.current_hash;
  }

  console.log(`CHAIN INTACT (${rows.length} rows checked)`);
}

main().catch((err) => {
  console.error('Could not verify chain:', err.message);
  process.exit(2);
});
