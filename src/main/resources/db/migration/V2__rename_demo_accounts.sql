-- Rename the seeded demo identity while retaining balances and ledger references.
INSERT INTO accounts (vpa, holder_name, balance, device_public_key, version)
SELECT 'rahul@demo', 'Rahul', balance, NULL, version FROM accounts WHERE vpa = 'alice@demo';
UPDATE transactions SET sender_vpa = 'rahul@demo' WHERE sender_vpa = 'alice@demo';
UPDATE transactions SET receiver_vpa = 'rahul@demo' WHERE receiver_vpa = 'alice@demo';
DELETE FROM accounts WHERE vpa = 'alice@demo';

-- Rename the seeded demo identity while retaining balances and ledger references.
INSERT INTO accounts (vpa, holder_name, balance, device_public_key, version)
SELECT 'priya@demo', 'Priya', balance, NULL, version FROM accounts WHERE vpa = 'bob@demo';
UPDATE transactions SET sender_vpa = 'priya@demo' WHERE sender_vpa = 'bob@demo';
UPDATE transactions SET receiver_vpa = 'priya@demo' WHERE receiver_vpa = 'bob@demo';
DELETE FROM accounts WHERE vpa = 'bob@demo';

-- Rename the seeded demo identity while retaining balances and ledger references.
INSERT INTO accounts (vpa, holder_name, balance, device_public_key, version)
SELECT 'neha@demo', 'Neha', balance, NULL, version FROM accounts WHERE vpa = 'carol@demo';
UPDATE transactions SET sender_vpa = 'neha@demo' WHERE sender_vpa = 'carol@demo';
UPDATE transactions SET receiver_vpa = 'neha@demo' WHERE receiver_vpa = 'carol@demo';
DELETE FROM accounts WHERE vpa = 'carol@demo';

-- Rename the seeded demo identity while retaining balances and ledger references.
INSERT INTO accounts (vpa, holder_name, balance, device_public_key, version)
SELECT 'amit@demo', 'Amit', balance, NULL, version FROM accounts WHERE vpa = 'dave@demo';
UPDATE transactions SET sender_vpa = 'amit@demo' WHERE sender_vpa = 'dave@demo';
UPDATE transactions SET receiver_vpa = 'amit@demo' WHERE receiver_vpa = 'dave@demo';
DELETE FROM accounts WHERE vpa = 'dave@demo';
