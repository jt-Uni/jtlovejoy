<?php
require __DIR__ . '/../controllers/adminRequestsController.php'; // This should set $requests
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin - Evaluation Requests</title>
  <link rel="stylesheet" href="../../public/css/style.css">
</head>

<body>
  <div class="container">
    <h1>Evaluation Requests</h1>

    <p><a href="dashboard.php" class="btn">Back to Dashboard</a></p>

    <?php if (!empty($requests) && count($requests) > 0): ?>
      <table>
        <thead>
          <tr>
            <th>User Name</th>
            <th>Email</th>
            <th>Comment</th>
            <th>Contact Method</th>
            <th>Photo</th>
            <th>Created At</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($requests as $request): ?>
            <tr>
              <td><?php echo htmlspecialchars($request['user_name']); ?></td>
              <td><?php echo htmlspecialchars($request['user_email']); ?></td>
              <td><?php echo htmlspecialchars($request['comment']); ?></td>
              <td><?php echo htmlspecialchars($request['contact_method']); ?></td>
              <td>
                <a href="../../uploads/<?php echo htmlspecialchars($request['photo']); ?>" target="_blank">View</a>
              </td>
              <td><?php echo htmlspecialchars($request['created_at']); ?></td>
              <td>
                <form action="../controllers/deleteRequestController.php" method="POST"
                  onsubmit="return confirm('Are you sure you want to delete this request?');">
                  <input type="hidden" name="request_id" value="<?php echo $request['id']; ?>">
                  <button type="submit">Delete</button>
                </form>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    <?php else: ?>
      <p>No evaluation requests found.</p>
    <?php endif; ?>
  </div>
</body>

</html>