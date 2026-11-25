CREATE DATABASE IF NOT EXISTS secureloan
  CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE secureloan;

DROP VIEW  IF EXISTS cashier_loans;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS loans;
DROP TABLE IF EXISTS customers;
DROP TABLE IF EXISTS app_users;

CREATE TABLE app_users (
  user_id       INT NOT NULL AUTO_INCREMENT,
  username      VARCHAR(50)  NOT NULL,
  password_hash VARCHAR(100) NOT NULL,
  role          ENUM('officer','senior_officer','cashier','admin','auditor')
                DEFAULT 'officer',
  PRIMARY KEY (user_id),
  UNIQUE KEY username (username)
) ENGINE=InnoDB;

CREATE TABLE customers (
  customer_id INT NOT NULL AUTO_INCREMENT,
  full_name   VARCHAR(100) NOT NULL,
  national_id VARBINARY(255) DEFAULT NULL,
  phone       VARCHAR(20)  DEFAULT NULL,
  created_at  TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (customer_id)
) ENGINE=InnoDB;

CREATE TABLE loans (
  loan_id       INT NOT NULL AUTO_INCREMENT,
  customer_id   INT NOT NULL,
  amount        DECIMAL(12,2) NOT NULL,
  interest_rate DECIMAL(5,2)  NOT NULL,
  status        ENUM('PENDING','APPROVED','REJECTED','ACTIVE','PAID','DEFAULTED')
                NOT NULL DEFAULT 'PENDING',
  created_by    VARCHAR(50) NULL,
  approved_by   VARCHAR(50) NULL,
  PRIMARY KEY (loan_id),
  KEY customer_id (customer_id),
  CONSTRAINT loans_ibfk_1 FOREIGN KEY (customer_id)
    REFERENCES customers (customer_id),
  CONSTRAINT chk_four_eyes
    CHECK (approved_by IS NULL OR approved_by <> created_by)
) ENGINE=InnoDB;

CREATE TABLE audit_log (
  log_id        BIGINT AUTO_INCREMENT PRIMARY KEY,
  db_user       VARCHAR(100) NOT NULL,
  action        VARCHAR(10)  NOT NULL,
  loan_id       INT          NULL,
  old_value     TEXT         NULL,
  new_value     TEXT         NULL,
  previous_hash CHAR(64)     NOT NULL,
  current_hash  CHAR(64)     NOT NULL,
  changed_at    DATETIME     NOT NULL
) ENGINE=InnoDB;

CREATE VIEW cashier_loans AS
SELECT l.loan_id, c.full_name, l.amount, l.status
FROM loans l
JOIN customers c ON c.customer_id = l.customer_id;
