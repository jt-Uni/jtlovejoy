<?php
require __DIR__ . '/../controllers/forgotPasswordController.php';
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forgot Password</title>
  <link rel="stylesheet" href="../../public/css/style.css">
</head>

<body>
  <div class="container">
    <h1>Forgot Password</h1>

    <?php if (!empty($errorMessage)) { ?>
      <div class="error"> <?php echo htmlspecialchars($errorMessage); ?> </div>
    <?php } ?>

    <form action="forgotPassword.php" method="POST">
      <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">

      <label for="email">Enter your registered email:</label>
      <input type="email" name="email" required><br>

      <button type="submit">Request Password Reset</button>
    </form>

    <p><a href="login.php">Back to Login</a></p>
  </div>
</body>

</html>