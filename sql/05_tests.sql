-- =========================================================
-- SECURELOAN TEST MATRIX (Member 2)
-- File: 05_tests.sql
-- =========================================================

-- ---------------------------------------------------------
-- TEST 1: Column-Level Permissions (Loan Officer)
-- Connection: Log in as 'loan_officer'@'localhost'
-- EXPECTED RESULT: ERROR 1143 (Denied on column 'amount')
-- ---------------------------------------------------------
USE secureloan;

-- Try to change the interest rate (Should FAIL)
UPDATE loans SET interest_rate = 20.00 WHERE loan_id = 1;

-- Try to change the loan amount (Should FAIL)
UPDATE loans SET amount = 50000 WHERE loan_id = 1;

-- Try to change status (Should SUCCEED - Column permission allows this)
UPDATE loans SET status = 'APPROVED' WHERE loan_id = 1;


-- ---------------------------------------------------------
-- TEST 2: Separation of Duties (Admin)
-- Connection: Log in as 'admin'@'localhost'
-- EXPECTED RESULT: ERROR 1142 (Denied on table 'audit_log')
-- ---------------------------------------------------------
USE secureloan;

-- Try to view the audit log (Should FAIL)
SELECT * FROM audit_log;

-- Try to delete a log entry (Should FAIL)
DELETE FROM audit_log WHERE log_id = 1;


-- ---------------------------------------------------------
-- TEST 3: View Security and Base Table Protection (Cashier)
-- Connection: Log in as 'cashier'@'localhost'
-- EXPECTED RESULT: ERROR 1142 (Denied on table 'customers')
-- ---------------------------------------------------------
USE secureloan;

-- Try to view the national ID (Should FAIL)
SELECT national_id FROM customers;

-- Try to view the cashier view (Should SUCCEED)
SELECT * FROM cashier_loans;


-- ---------------------------------------------------------
-- TEST 4: Four-Eyes Rule / Constraints (Self-Approval)
-- Connection: Log in as 'senior_officer'@'localhost' (or root)
-- EXPECTED RESULT: ERROR 3819 (Check constraint violated)
-- ---------------------------------------------------------
-- (Note: You can run this as root to test the constraint)
USE secureloan;

-- Insert a loan created by 'senior_officer'
INSERT INTO loans (customer_id, amount, interest_rate, status, created_by) 
VALUES (1, 15000, 10.0, 'PENDING', 'senior_officer');

-- Try to approve it as the SAME person (Should FAIL due to CHECK constraint)
UPDATE loans 
SET status = 'APPROVED', approved_by = 'senior_officer' 
WHERE created_by = 'senior_officer' AND status = 'PENDING';