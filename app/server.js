const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('./db'); 

const app = express();
app.use(express.json()); 
app.use(express.static('public')); 

// --- ROUTE 1: SECURE LOGIN ---
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: "Missing fields" });

        const [rows] = await pool.execute('SELECT * FROM app_users WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ error: "Invalid credentials" });

        res.json({ message: "Login successful", user: { username: user.username, role: user.role } });
    } catch (error) {
        // THIS IS THE CRUCIAL PART: It prints the exact database error to your terminal
        console.error("DATABASE ERROR: ", error.message); 
        res.status(500).json({ error: "Server error: " + error.message });
    }
});

// --- ROUTE 2: REGISTER A NEW USER (For testing) ---
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        if (!username || !password) return res.status(400).json({ error: "Missing fields" });

        // Hash the password securely
        const password_hash = await bcrypt.hash(password, 10);
        
        await pool.execute(
            'INSERT INTO app_users (username, password_hash, role) VALUES (?, ?, ?)',
            [username, password_hash, role || 'officer']
        );
        res.json({ message: "User created successfully!" });
    } catch (error) {
        console.error("DATABASE ERROR: ", error.message);
        res.status(500).json({ error: "Registration failed: " + error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Clean API running on http://localhost:${PORT}`));