<?php
session_start();
require __DIR__ . '/../../config/config.php';

// Check if the user is an admin
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    die("Access denied. Admins only.");
}

// Fetch evaluation requests from the database
try {
    $stmt = $pdo->query("
        SELECT 
            evaluation_requests.id, 
            users.name AS user_name, 
            users.email AS user_email, 
            evaluation_requests.comment, 
            evaluation_requests.contact_method, 
            evaluation_requests.photo, 
            evaluation_requests.created_at 
        FROM evaluation_requests
        INNER JOIN users ON evaluation_requests.user_id = users.id
        ORDER BY evaluation_requests.created_at DESC;
    ");
    $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Database error fetching requests: " . $e->getMessage());
    $requests = []; // Default to an empty array on failure
}
