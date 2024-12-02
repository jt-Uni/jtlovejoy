<?php
require __DIR__ . '/../controllers/resetPasswordController.php';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <link rel="stylesheet" href="../../public/css/style.css">
</head>
<body>
    <div class="container">
        <h1>Reset Password</h1>

        <?php if (!empty($errorMessage)) { ?>
            <div class="error"> <?php echo htmlspecialchars($errorMessage); ?> </div>
        <?php } ?>

        <form action="resetPassword.php" method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
            <input type="hidden" name="reset_token" value="<?php echo htmlspecialchars($reset_token); ?>">

            <label for="password">Enter New Password:</label>
            <input type="password" name="password" required><br>

            <label for="confirm_password">Confirm New Password:</label>
            <input type="password" name="confirm_password" required><br>

            <button type="submit">Reset Password</button>
        </form>

        <p><a href="login.php">Back to Login</a></p>
    </div>
</body>
</html>
