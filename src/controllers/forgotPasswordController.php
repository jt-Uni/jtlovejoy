<?php
require __DIR__ . '/../../vendor/autoload.php'; // Ensure correct path to autoload.php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

use Dotenv\Dotenv;


// forgotPassword.php
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;

$dotenv = Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();

try {
    // Validate and sanitize email input
    if (empty($_POST['email']) || !filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
        throw new Exception("Invalid or missing email address.");
    }
    $email = htmlspecialchars($_POST['email']);

    // Generate a secure reset link
    $resetToken = bin2hex(random_bytes(16)); // Secure token generation
    $resetLink = "http://localhost:8080/src/views/resetPassword.php?token=$resetToken";

    // Initialize PHPMailer
    $mail = new PHPMailer(true);

    // SMTP configuration (using SendGrid)
    $mail->isSMTP();
    $mail->Host = 'smtp.sendgrid.net';
    $mail->SMTPAuth = true;
    $mail->Username = 'apikey'; // SendGrid uses 'apikey' as the username
    $mail->Password = ($_ENV['SENDGRID_API_KEY']); // Use environment variable for security
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port = 587;

    // Email settings
    $mail->setFrom('dev.jamesT@gmail.com', 'Your Application'); // Replace with your email and app name
    $mail->addAddress($email); // Add recipient

    // Email content
    $mail->isHTML(true);
    $mail->Subject = 'Password Reset Request';
    $mail->Body = "Hello,<br><br>We received a request to reset your password. You can reset it by clicking the link below:<br>
                   <a href=\"$resetLink\">Reset Password</a><br><br>
                   If you did not request this, please ignore this email.<br><br>Thank you.";

    // Send the email
    $mail->send();

    // Output success response
    echo json_encode([
        "success" => true,
        "message" => "If the email exists in our system, you will receive a reset link."
    ]);
} catch (Exception $e) {
    // Output error response
    echo json_encode([
        "success" => false,
        "message" => "Email could not be sent. Error: " . $e->getMessage()
    ]);
}
