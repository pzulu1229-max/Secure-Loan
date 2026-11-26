const pool = require('./db');
const bcrypt = require('bcrypt');

async function createUsers() {
    const hash = await bcrypt.hash('password123', 10);
    
    // Insert Officer
    await pool.execute(
        "INSERT INTO app_users (username, password_hash, role) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)",
        ['officer1', hash, 'officer']
    );
    
    // Insert Auditor
    await pool.execute(
        "INSERT INTO app_users (username, password_hash, role) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)",
        ['auditor1', hash, 'auditor']
    );

    // Insert Admin
    await pool.execute(
        "INSERT INTO app_users (username, password_hash, role) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)",
        ['admin1', hash, 'admin']
    );
    
    console.log("✅ Success! Users 'officer1', 'auditor1', and 'admin1' created with password 'password123'");
    process.exit(0);
}

createUsers();