<?php
require __DIR__ . '/../controllers/loginController.php';
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <script src="https://www.google.com/recaptcha/enterprise.js" async defer></script>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login</title>
  <link rel="stylesheet" href="../../public/css/style.css">
</head>

<body>
  <div class="container">
    <h1>Login</h1>

    <?php if (!empty($errorMessage)) { ?>
      <div class="error"><?php echo htmlspecialchars($errorMessage); ?></div>
    <?php } ?>

    <form action="login.php" method="POST">
      <label for="email">Email:</label>
      <input type="email" name="email" required><br>

      <label for="password">Password:</label>
      <input type="password" name="password" required><br>

      <div class="g-recaptcha" data-sitekey="6Leal5IqAAAAAPqLyPcvTiiHDhjolvOkhxdQmdBq" data-action="LOGIN"></div>
      <br />

      <button type="submit">Login</button>
    </form>

    <p>Don't have an account? <a href="register.php">Register here</a></p>

    <p><a href="forgotPassword.php">Forgot password?</a></p>
  </div>
</body>

</html>