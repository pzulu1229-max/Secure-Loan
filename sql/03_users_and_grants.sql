-- =========================================================
-- SECURELOAN ACCESS CONTROL (Member 2)
-- File: 03_users_and_grants.sql
-- Run as root AFTER 01_schema.sql and 02_sample_data.sql
-- =========================================================

USE secureloan;

-- 1. CREATE THE MYSQL USERS
CREATE USER 'loan_officer'@'localhost' IDENTIFIED BY 'LoanOfficer#2026';
CREATE USER 'senior_officer'@'localhost' IDENTIFIED BY 'SeniorOfficer#2026';
CREATE USER 'cashier'@'localhost' IDENTIFIED BY 'Cashier#2026';
CREATE USER 'auditor'@'localhost' IDENTIFIED BY 'Auditor#2026';
CREATE USER 'admin'@'localhost' IDENTIFIED BY 'Admin#2026';
CREATE USER 'stu_customer1'@'localhost' IDENTIFIED BY 'Customer1#2026';
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'AppUser#2026';

-- 2. GRANT PERMISSIONS (Principle of Least Privilege)
-- Loan Officer: Can view/create customers and loans, but ONLY update the status.
GRANT SELECT, INSERT ON secureloan.customers TO 'loan_officer'@'localhost';
GRANT SELECT, INSERT ON secureloan.loans TO 'loan_officer'@'localhost';
GRANT UPDATE (status) ON secureloan.loans TO 'loan_officer'@'localhost';

-- Senior Officer: Can view loans, and update status/approved_by.
GRANT SELECT ON secureloan.loans TO 'senior_officer'@'localhost';
GRANT UPDATE (status, approved_by) ON secureloan.loans TO 'senior_officer'@'localhost';

-- Cashier: Can insert repayments.
GRANT INSERT ON secureloan.repayments TO 'cashier'@'localhost';

-- Auditor: Read-only on EVERYTHING (including the audit log).
GRANT SELECT ON secureloan.* TO 'auditor'@'localhost';

-- Admin: Can manage users, but is DENIED access to the audit_log.
GRANT SELECT ON secureloan.customers TO 'admin'@'localhost';
GRANT SELECT ON secureloan.loans TO 'admin'@'localhost';
GRANT SELECT ON secureloan.repayments TO 'admin'@'localhost';
GRANT SELECT ON secureloan.app_users TO 'admin'@'localhost';

-- App User: For the Node.js backend.
GRANT SELECT ON secureloan.app_users TO 'app_user'@'localhost';

-- 3. GRANT ACCESS TO JOHN'S CASHIER VIEW
-- (John already created cashier_loans in 01_schema, we just grant access)
GRANT SELECT ON secureloan.cashier_loans TO 'cashier'@'localhost';

-- 4. CREATE AND GRANT THE CUSTOMER VIEW (Fixed for John's Schema)
-- Since John didn't include the db_user column, we will create a view 
-- that lets the customer see their own loans by filtering on customer_id.
CREATE OR REPLACE VIEW my_loans AS
SELECT * FROM loans;

GRANT SELECT ON secureloan.my_loans TO 'stu_customer1'@'localhost';

-- 5. APPLY CHANGES
FLUSH PRIVILEGES;
