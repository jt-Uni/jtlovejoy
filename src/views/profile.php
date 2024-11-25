<?php
require __DIR__ . '/../controllers/profileController.php';
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Profile</title>
    <link rel="stylesheet" href="../../public/css/style.css">
</head>

<body>
    <div class="container">
        <h1>Edit Profile</h1>

        <?php if (!empty($errorMessage)) { ?>
            <div class="error"><?php echo htmlspecialchars($errorMessage); ?></div>
        <?php } ?>

        <?php if (!empty($successMessage)) { ?>
            <div class="success"><?php echo htmlspecialchars($successMessage); ?></div>
        <?php } ?>

        <form action="profile.php" method="POST">
            <label for="name">Name:</label>
            <input type="text" name="name" value="<?php echo htmlspecialchars($user['name']); ?>" required><br>
            
            <label for="email">Email:</label>
            <input type="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required><br>
            
            <label for="contact">Contact Number:</label>
            <input type="text" name="contact" value="<?php echo htmlspecialchars($user['contact_number']); ?>" required><br>
            
            <button type="submit">Update Profile</button>
        </form>

        <p><a href="dashboard.php">Back to Dashboard</a></p>
    </div>
</body>

</html>