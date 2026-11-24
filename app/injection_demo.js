require('dotenv').config();
const mysql = require('mysql2/promise');

async function vulnerableLogin(conn, username, password) {
    const query = `SELECT * FROM app_users WHERE username = '${username}' AND password_hash = '${password}'`;
    console.log(`\n[VULNERABLE] ${query}`);
    const [rows] = await conn.query(query);
    return rows;
}

async function secureLogin(conn, username, password) {
    const query = 'SELECT * FROM app_users WHERE username = ? AND password_hash = ?';
    console.log(`\n[SECURE] ${query} | Params: [${username}, ${password}]`);
    const [rows] = await conn.execute(query, [username, password]);
    return rows;
}

async function runDemo() {
    const conn = await mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'app_user',
        password: process.env.DB_PASS,
        database: process.env.DB_NAME || 'secureloan'
    });

    console.log("=== HACKER ATTACK ===");
    const attackUser = "admin' #"; 
    const attackPass = "anything"; 

    console.log("\n--- VULNERABLE ---");
    const vAttack = await vulnerableLogin(conn, attackUser, attackPass);
    console.log(vAttack.length > 0 ? "🚨 BREACH! Logged in as: " + vAttack[0].username : "Blocked");

    console.log("\n--- SECURE ---");
    const sAttack = await secureLogin(conn, attackUser, attackPass);
    console.log(sAttack.length > 0 ? "🚨 BREACH!" : "✅ ATTACK BLOCKED");

    await conn.end();
}
runDemo().catch(console.error);