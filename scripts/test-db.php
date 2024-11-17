<?php
require __DIR__ . '/../config/config.php'; // Include the database configuration

try {
    // Test the database connection
    echo "Testing database connection...<br>";
    
    $stmt = $pdo->query("SHOW TABLES");
    
    echo "Connected successfully! Here are the tables and their contents:<br>";
    
    // Fetch and output each table
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        // Dynamically get the column name for tables in the database
        $tableName = reset($row); // Gets the first column (table name)
        echo "<strong>Table: $tableName</strong><br>";
        
        // Query to select all data from the current table
        $tableStmt = $pdo->query("SELECT * FROM `$tableName`");
        
        // Fetch and output the rows for the current table
        while ($tableRow = $tableStmt->fetch(PDO::FETCH_ASSOC)) {
            echo "<pre>";
            print_r($tableRow); // Print each row in a readable format
            echo "</pre>";
        }
        echo "<br><br>"; // Add some space between tables
    }
} catch (PDOException $e) {
    // Handle connection errors
    echo "Database connection failed: " . $e->getMessage();
}
?>
