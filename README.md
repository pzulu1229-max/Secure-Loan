# Secure-Loan
# SecureLoan: A Secure Loan Management Database
**Course:** BIT3360: Advanced Databases  
**Institution:** Zambia University College of Technology  
**Assignment:** Group Project - Database Security  
**Submission Date:** 26/11/26

---

## 📖 Project Overview
**SecureLoan** is a prototype database system designed for a microfinance lender. The primary goal of this project is not just to store loan data, but to demonstrate how a database can be protected so that **nobody can do more than their job allows, and every important change leaves evidence.**

### The Problem It Solves
In a lending business, staff might attempt to change interest rates, approve their own loans, or hide edits. Attackers might use SQL injection to break in. SecureLoan demonstrates how to use database-level permissions, approval rules, audit logs, and safe queries to stop or expose these threats.

---

## 👥 Group Members & Roles (Group Assignment)

This project was built by a team of four, with each member taking the lead on a specific security pillar:

| Member Name | Student ID | Role | Key Contributions |
| :--- | :--- | :--- | :--- |
| **John Otala** | 2410100 | **Database Designer** | Designed tables, constraints, sample data, views (`my_loans`, `cashier_loans`), and the ER diagram. (`01_schema.sql`, `02_sample_data.sql`) |
| **Prince Zulu** | 2410237 | **Access Control Lead** | Created users, applied `GRANT`/`REVOKE`, enforced column-level permissions, implemented the four-eyes rule, and wrote the test matrix with screenshots. (`03_users_and_grants.sql`, `05_tests.sql`) |
| **Ernest Chiwala** | 2410170 | **Backend & Security Developer** | Built the Express API, implemented bcrypt login, role checks, and developed the vulnerable vs. parameterised login demonstration. (`server.js`, `injection_demo.js`) |
| **Martin Muloshi** | 2410009 | **Audit & Presentation Lead** | Developed audit triggers, the hash-chain logic, the tamper-detection script, and compiled the final presentation and documentation. (`04_audit_triggers.sql`, `verify_chain.js`) |

---

## 🛡️ Security Features Demonstrated
1. **Role-based access (GRANT / REVOKE):** Each user gets only the permissions they need.
2. **Column-level permissions:** Loan officers can change a loan's status, but never its amount or interest rate.
3. **Views:** Customers see only their own loans; cashiers see loans without national ID numbers.
4. **Four-eyes approval:** Large loans stay `PENDING` until a different officer approves. A constraint rejects self-approval.
5. **Audit log (triggers):** Every change to a loan is recorded (who, when, old value, new value).
6. **Hash-chained audit log:** Each log row stores the hash of the previous one, detecting tampering.
7. **Separation of duties:** The Admin manages users but is denied access to read the audit log.
8. **Parameterised queries:** SQL injection is demonstrated and blocked.
9. **Password hashing (bcrypt):** Passwords are never stored in plain text.

---

## 📂 Folder Structure
```text
secureloan/
│
├── sql/
│   ├── 01_schema.sql               # Database, tables, constraints
│   ├── 02_sample_data.sql          # Fake customers, loans, repayments
│   ├── 03_users_and_grants.sql     # Users, GRANTs, Views
│   ├── 04_audit_triggers.sql       # Audit triggers, hash-chain logic
│   └── 05_tests.sql                # Allowed vs. denied permission tests
│
├── app/
│   ├── server.js                   # Express API, bcrypt login, parameterised queries
│   ├── injection_demo.js           # Vulnerable vs Safe login demonstration
│   └── verify_chain.js             # Recomputes hashes to detect tampering
│
├── screenshots/
│   └── (Evidence of allowed and denied results)
│
├── README.md                       # This file
└── SecureLoan_Presentation.pptx    # Research and prototype slides


🚀 How to Run the Project
Prerequisites
MySQL Server 8.0.16 or newer (Must support CHECK constraints).

MySQL Workbench (To run SQL scripts).

Node.js (LTS) and npm (To run the Express backend).

VS Code (Or any code editor).

Postman (For API testing).

Step 1: Database Setup
Open MySQL Workbench and connect as root.

Run the SQL files in this exact order:

Run 01_schema.sql (Creates the database and tables).

Run 02_sample_data.sql (Inserts fake data).

Run 03_users_and_grants.sql (Creates users and views).

Run 04_audit_triggers.sql (Sets up the audit log).

Run 05_tests.sql (Tests the permissions).

Step 2: Application Setup (Backend)
Open your terminal and navigate to the app folder.

Install the required packages:

bash
npm install express mysql2 bcrypt dotenv
(Note: If bcrypt fails on Windows, use npm install bcryptjs instead).

Create a .env file in the app folder and add your database credentials:

env
DB_HOST=localhost
DB_USER=app_user
DB_PASS=AppUser#2026
DB_NAME=secureloan
Start the server:

bash
node server.js
Step 3: Run the Demonstrations
SQL Injection Demo: Run node injection_demo.js in the terminal to see the vulnerable login bypassed and the safe login defended.

Audit Tamper Check: Run node verify_chain.js in the terminal. It will read the audit_log table and output CHAIN INTACT or TAMPERING DETECTED.

⚠️ Honest Limitation
While the hash chain makes tampering detectable, it cannot stop someone with full root control who rebuilds the entire chain from scratch. No system is 100% secure.

📚 References & Sources
(Add your references here for the research part of the assignment, e.g., MySQL Documentation on GRANT, OWASP Top 10 for SQL Injection, NIST guidelines on Access Control).
