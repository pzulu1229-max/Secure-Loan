-- 04_audit_triggers.sql  (Member 4: Audit and Presentation Lead)
-- Run as root/admin AFTER 01_schema.sql, 02_sample_data.sql and 03_users_and_grants.sql.
-- The triggers run with the definer's rights, so loan_officer, senior_officer etc.
-- do NOT need INSERT on audit_log (and must not be given it).

USE secureloan;

-- audit_log must keep these as plain text columns (NOT the JSON type),
-- otherwise MySQL reformats the text and the hashes will not match.
CREATE TABLE IF NOT EXISTS audit_log (
  log_id        BIGINT AUTO_INCREMENT PRIMARY KEY,
  db_user       VARCHAR(100) NOT NULL,
  action        VARCHAR(10)  NOT NULL,
  loan_id       INT          NULL,
  old_value     TEXT         NULL,
  new_value     TEXT         NULL,
  previous_hash CHAR(64)     NOT NULL,
  current_hash  CHAR(64)     NOT NULL,
  changed_at    DATETIME     NOT NULL
);

DROP TRIGGER IF EXISTS loans_after_insert;
DROP TRIGGER IF EXISTS loans_after_update;
DROP TRIGGER IF EXISTS loans_after_delete;
DROP PROCEDURE IF EXISTS write_audit;

DELIMITER $$

-- One place that builds the hash chain, so all triggers behave the same.
CREATE PROCEDURE write_audit(
  IN p_action  VARCHAR(10),
  IN p_loan_id INT,
  IN p_old     TEXT,
  IN p_new     TEXT
)
BEGIN
  DECLARE v_prev CHAR(64);
  DECLARE v_user VARCHAR(100);
  DECLARE v_time DATETIME;

  -- USER() = the account that ran the statement (e.g. loan_officer@localhost).
  -- Do NOT use CURRENT_USER() here: inside a trigger it returns the DEFINER.
  SET v_user = USER();
  SET v_time = NOW();

  -- Previous row's hash; FOR UPDATE stops two changes reading the same "last" row.
  SET v_prev = IFNULL(
    (SELECT current_hash FROM audit_log ORDER BY log_id DESC LIMIT 1 FOR UPDATE),
    REPEAT('0', 64)   -- genesis value for the first row
  );

  INSERT INTO audit_log
    (db_user, action, loan_id, old_value, new_value, previous_hash, current_hash, changed_at)
  VALUES (
    v_user, p_action, p_loan_id, p_old, p_new, v_prev,
    SHA2(CONCAT_WS('|',
      v_prev,
      v_user,
      p_action,
      IFNULL(p_loan_id, ''),
      IFNULL(p_old, ''),
      IFNULL(p_new, ''),
      DATE_FORMAT(v_time, '%Y-%m-%d %H:%i:%s')
    ), 256),
    v_time
  );
END$$

CREATE TRIGGER loans_after_insert AFTER INSERT ON loans
FOR EACH ROW
BEGIN
  CALL write_audit('INSERT', NEW.loan_id, NULL,
    CAST(JSON_OBJECT('customer_id', NEW.customer_id, 'amount', NEW.amount,
                     'interest_rate', NEW.interest_rate, 'status', NEW.status,
                     'created_by', NEW.created_by, 'approved_by', NEW.approved_by) AS CHAR));
END$$

CREATE TRIGGER loans_after_update AFTER UPDATE ON loans
FOR EACH ROW
BEGIN
  CALL write_audit('UPDATE', NEW.loan_id,
    CAST(JSON_OBJECT('amount', OLD.amount, 'interest_rate', OLD.interest_rate,
                     'status', OLD.status, 'approved_by', OLD.approved_by) AS CHAR),
    CAST(JSON_OBJECT('amount', NEW.amount, 'interest_rate', NEW.interest_rate,
                     'status', NEW.status, 'approved_by', NEW.approved_by) AS CHAR));
END$$

-- Nobody is granted DELETE, but log it anyway in case that ever changes.
CREATE TRIGGER loans_after_delete AFTER DELETE ON loans
FOR EACH ROW
BEGIN
  CALL write_audit('DELETE', OLD.loan_id,
    CAST(JSON_OBJECT('customer_id', OLD.customer_id, 'amount', OLD.amount,
                     'interest_rate', OLD.interest_rate, 'status', OLD.status,
                     'created_by', OLD.created_by, 'approved_by', OLD.approved_by) AS CHAR),
    NULL);
END$$

DELIMITER ;

-- ---------------------------------------------------------------
-- Quick checks (run as the real users, not root)
--   As loan_officer:   UPDATE loans SET status='APPROVED' WHERE loan_id=1;
--   As auditor:        SELECT * FROM audit_log ORDER BY log_id;
--   Tamper demo (root): UPDATE audit_log SET new_value = REPLACE(new_value,'PENDING','APPROVED') WHERE log_id = 2;
--   Then:              node app/verify_chain.js   -> TAMPERING DETECTED
-- ---------------------------------------------------------------
