<?php
session_start();

// Redirect to dashboard if the user is already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: src/views/dashboard.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to the Antique Evaluation System</title>
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <div class="container">
        <h1>Welcome to Lovejoy's Antique Evaluation System</h1>
        <p>Securely register, log in, and request evaluations for your antiques.</p>

        <div class="navigation">
            <ul>
                <li><a href="src/views/register.php" class="btn">Register</a></li>
                <li><a href="src/views/login.php" class="btn">Login</a></li>
                <li><a href="src/views/forgotPassword.php" class="btn">Forgot Password</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
