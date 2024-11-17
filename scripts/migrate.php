<?php
require __DIR__ . '/../config/config.php'; // Include database connection

// SQL to create the table
$sql = "
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        contact_number VARCHAR(15),
        role ENUM('user', 'admin') DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
";

try {
    $pdo->exec($sql);
    echo "Table created successfully or already exists.";
} catch (PDOException $e) {
    echo "Error creating table: " . $e->getMessage();
}
