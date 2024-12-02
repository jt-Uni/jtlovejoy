<?php
require __DIR__ . '/../controllers/registerController.php';
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register</title>
  <link rel="stylesheet" href="../../public/css/style.css">
  <script src="../../public/js/passwordStrength.js"></script>
</head>

<body>
  <div class="container">
    <h1>Register</h1>

    <?php if (!empty($errorMessage)) { ?>
      <div class="error"><?php echo htmlspecialchars($errorMessage); ?></div>
    <?php } ?>

    <form action="register.php" method="POST">
      <label for="name">Name:</label>
      <input type="text" name="name" required><br>

      <label for="email">Email:</label>
      <input type="email" name="email" required><br>

      <label for="password">Password:</label>
      <input type="password" name="password" id="password" required><br>

      <div id="password-strength">
        <div id="strength-bar"></div>
      </div>
      <div id="strength-text"></div>

      <label for="contact">Contact Number:</label>
      <input type="text" name="contact" required><br>

      <button type="submit">Register</button>
    </form>

    <p>Already have an account? <a href="login.php">Login here</a></p>
  </div>
</body>

</html>