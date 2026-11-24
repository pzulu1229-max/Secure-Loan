const pool = require('./db');
const bcrypt = require('bcrypt');

async function createUser() {
    const password = 'password123';
    const hash = await bcrypt.hash(password, 10);
    
    // Delete the old fake user if it exists
    await pool.execute("DELETE FROM app_users WHERE username = 'officer1'");
    
    // Insert the new user with the real hash
    await pool.execute(
        "INSERT INTO app_users (username, password_hash, role) VALUES (?, ?, ?)",
        ['officer1', hash, 'officer']
    );
    
    console.log("✅ Success! User 'officer1' created with password 'password123'");
    process.exit(0);
}

createUser();