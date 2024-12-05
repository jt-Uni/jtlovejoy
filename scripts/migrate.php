<?php
require __DIR__ . '/../config/config.php';

try {
    $sql = "
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            contact_number VARCHAR(15),
            role ENUM('user', 'admin') DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reset_token VARCHAR(64),
            reset_token_expiry DATETIME
        );

        CREATE TABLE IF NOT EXISTS evaluation_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            comment TEXT NOT NULL,
            contact_method ENUM('phone', 'email') NOT NULL,
            photo VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ";

    $pdo->exec($sql);
    echo "Tables created successfully or already exist.";
} catch (PDOException $e) {
    error_log("Database Migration Error: " . $e->getMessage());
    echo "Error creating tables: " . htmlspecialchars($e->getMessage());
}
