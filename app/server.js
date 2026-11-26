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
        console.error("DATABASE ERROR: ", error.message); 
        res.status(500).json({ error: "Server error: " + error.message });
    }
});

// --- ROUTE 2: REGISTER A NEW USER ---
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        if (!username || !password) return res.status(400).json({ error: "Missing fields" });

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

// --- ROUTE 3: GET ALL LOANS ---
app.get('/api/loans', async (req, res) => {
    try {
        const [rows] = await pool.execute(
            'SELECT l.loan_id, c.full_name, l.amount, l.interest_rate, l.status, l.created_by, l.approved_by FROM loans l JOIN customers c ON l.customer_id = c.customer_id'
        );
        res.json(rows);
    } catch (error) {
        console.error("DATABASE ERROR: ", error.message);
        res.status(500).json({ error: error.message });
    }
});

// --- ROUTE 4: CREATE A LOAN ---
app.post('/api/loans', async (req, res) => {
    try {
        const { customer_id, amount, interest_rate, created_by } = req.body;
        await pool.execute(
            'INSERT INTO loans (customer_id, amount, interest_rate, created_by) VALUES (?, ?, ?, ?)',
            [customer_id, amount, interest_rate, created_by || 'system']
        );
        res.json({ message: "Loan created successfully!" });
    } catch (error) {
        console.error("DATABASE ERROR: ", error.message);
        res.status(500).json({ error: error.message });
    }
});

// --- ROUTE 5: GET AUDIT LOGS ---
app.get('/api/audit', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM audit_log ORDER BY log_id DESC LIMIT 10');
        res.json(rows);
    } catch (error) {
        console.error("DATABASE ERROR: ", error.message);
        res.status(500).json({ error: error.message });
    }
});

// --- ROUTE 6: APPROVE LOAN (Four-Eyes Principle) ---
app.put('/api/loans/:id/approve', async (req, res) => {
    try {
        const { approved_by } = req.body;
        const loanId = req.params.id;

        const [rows] = await pool.execute('SELECT created_by, status FROM loans WHERE loan_id = ?', [loanId]);
        if (rows.length === 0) return res.status(404).json({ error: "Loan not found" });
        
        const loan = rows[0];

        // Four-Eyes Principle: Creator cannot be the approver
        if (loan.created_by === approved_by) {
            return res.status(403).json({ error: "Four-Eyes Principle Violation: You cannot approve a loan you created." });
        }

        if (loan.status !== 'PENDING') {
            return res.status(400).json({ error: "Only PENDING loans can be approved." });
        }

        await pool.execute(
            'UPDATE loans SET status = ?, approved_by = ? WHERE loan_id = ?',
            ['ACTIVE', approved_by, loanId]
        );

        res.json({ message: "Loan approved successfully!" });
    } catch (error) {
        console.error("DATABASE ERROR: ", error.message);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Clean API running on http://localhost:${PORT}`));