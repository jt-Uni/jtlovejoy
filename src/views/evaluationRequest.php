<?php
require __DIR__ . '/../controllers/evaluationRequestController.php'; // Include the controller
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Evaluation Request</title>
    <link rel="stylesheet" href="../../public/css/style.css">
</head>
<body>
    <div class="container">
        <h1>Submit an Evaluation Request</h1>

        <?php if (!empty($errorMessage)) { ?>
            <div class="error"><?php echo htmlspecialchars($errorMessage); ?></div>
        <?php } ?>

        <form action="evaluationRequest.php" method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

            <label for="comment">Describe the object:</label>
            <textarea name="comment" rows="5" required></textarea><br>

            <label for="contact_method">Preferred Contact Method:</label>
            <select name="contact_method" required>
                <option value="phone">Phone</option>
                <option value="email">Email</option>
            </select><br>

            <label for="photo">Upload a Photo of the Object:</label>
            <input type="file" name="photo" accept="image/*" required><br>

            <button type="submit">Submit Request</button>
        </form>

        <p><a href="dashboard.php">Back to Dashboard</a></p>
    </div>
</body>
</html>
