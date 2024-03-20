-- Use the specified database (Replace 'chatdb' with your actual database name if different)
USE chatdb;

-- Drop tables if they already exist (to avoid conflicts during development/testing)
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS users;

-- Create 'users' table
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- Passwords will be stored as bcrypt hashes
    public_key VARCHAR(2048) NOT NULL,
    iv VARBINARY(16), -- For AES CBC mode encryption of user info
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create 'messages' table
CREATE TABLE messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    message_text TEXT NOT NULL, -- Consider storing encrypted messages here
    nonce VARBINARY(12), -- Nonce for AES GCM mode encryption of messages
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES users(user_id)
);

-- Optionally, insert some initial data for testing
-- Passwords here should be hashed using bcrypt in your application logic before insertion
INSERT INTO users (username, password, public_key, iv) VALUES ('Alice', '<bcrypt_hash>', '<public_key>', '<iv>');
INSERT INTO users (username, password, public_key, iv) VALUES ('Bob', '<bcrypt_hash>', '<public_key>', '<iv>');
