USE secureloan;

INSERT INTO customers (customer_id, full_name, national_id, phone) VALUES
  (1, 'Test Customer',   AES_ENCRYPT('123456/10/1', 'change_this_key'), '0970000000'),
  (2, 'Second Customer', AES_ENCRYPT('654321/10/1', 'change_this_key'), '0971111111');

INSERT INTO loans (loan_id, customer_id, amount, interest_rate, status, created_by, approved_by) VALUES
  (1, 1, 5000.00, 12.50, 'PENDING', 'loan_officer', NULL),
  (2, 2, 8000.00, 10.00, 'ACTIVE',  'loan_officer', 'senior_officer');
