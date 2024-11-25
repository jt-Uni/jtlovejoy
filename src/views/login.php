<?php
require __DIR__ . '/../controllers/loginController.php';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="../../public/css/style.css">
</head>
<body>
    <div class="container">
        <h1>Login</h1>

        <?php if (isset($errorMessage)) { ?>
            <div class="error"><?php echo $errorMessage; ?></div>
        <?php } ?>

        <form action="login.php" method="POST">
            <label for="email">Email:</label>
            <input type="email" name="email" required><br>
            
            <label for="password">Password:</label>
            <input type="password" name="password" required><br>
            
            <button type="submit">Login</button>
        </form>

        <p>Don't have an account? <a href="register.php">Register here</a></p>
    </div>
</body>
</html>