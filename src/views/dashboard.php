<?php
require __DIR__ . '/../controllers/dashboardController.php';
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard</title>
  <link rel="stylesheet" href="../../public/css/style.css">
</head>

<body>
  <div class="container">
    <h1>Welcome to Your Dashboard, <?php echo htmlspecialchars($user['name']); ?>!</h1>
    <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
    <p><strong>Contact Number:</strong> <?php echo htmlspecialchars($user['contact_number']); ?></p>

    <h2>Your Actions</h2>
    <ul>
      <li><a href="profile.php">Edit Profile</a></li>
      <li><a href="evaluationRequest.php">Submit an Evaluation Request</a></li>
      <li><a href="logout.php">Logout</a></li>

      <?php if ($_SESSION['role'] === 'admin'): ?>
        <li><a href="adminRequests.php">View Evaluation Requests</a></li>
      <?php endif; ?>
    </ul>
  </div>
</body>

</html>