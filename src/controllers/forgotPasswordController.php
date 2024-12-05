<?php
require __DIR__ . '/../../config/config.php';
require __DIR__ . '/../../vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

use Dotenv\Dotenv;

$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;

$dotenv = Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();

try {
  if (empty($_POST['email']) || !filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
    throw new Exception("Invalid or missing email address.");
  }
  $email = htmlspecialchars($_POST['email']);

  $resetToken = bin2hex(random_bytes(16));
  $resetLink = "http://localhost:8080/src/views/resetPassword.php?token=$resetToken";
  $expiryTime = date('Y-m-d H:i:s', strtotime('+1 hour'));

  $stmt = $pdo->prepare("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?");
  $stmt->execute([$resetToken, $expiryTime, $email]);

  if ($stmt->rowCount() === 0) {
    throw new Exception("Email not found or update failed.");
  }

  $mail = new PHPMailer(true);

  $mail->isSMTP();
  $mail->Host = 'smtp.gmail.com';
  $mail->SMTPAuth = true;
  $mail->Username = ($_ENV['GMAIL_USERNAME']);
  $mail->Password = ($_ENV['GMAIL_PASSWORD']);
  $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
  $mail->Port = 587;

  $mail->setFrom('james.steve.taylor@gmail.com', 'Lovejoys Antique');
  $mail->addAddress($email);

  $mail->isHTML(true);
  $mail->Subject = 'Password Reset Request';
  $mail->Body = "Hello,<br><br>We received a request to reset your password. You can reset it by clicking the link below:<br>
                 <a href=\"$resetLink\">Reset Password</a><br><br>
                 If you did not request this, please ignore this email.<br><br>Thank you.";

  $mail->send();

  echo json_encode([
    "success" => true,
    "message" => "If the email exists in our system, you will receive a reset link."
  ]);
} catch (Exception $e) {
  echo json_encode([
    "success" => false,
    "message" => "Error: " . $e->getMessage()
  ]);
}
