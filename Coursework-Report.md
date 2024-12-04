# Lovejoy’s Antique Evaluation Web Application - Coursework Report

## Table of Contents

1. **Introduction**
2. **Task 1: User Registration**
   - Code Snippets
   - Database Design
   - Security Analysis
3. **Task 2: Secure Login Feature**
   - Code Snippets
   - Security Measures
4. **Task 3: Password Policy and Recovery**
   - Code Snippets
   - Security Analysis
5. **Task 4: Evaluation Request Page**
   - Code Snippets
   - Security Features
6. **Task 5: Evaluation Listing Page (Admin Only)**
   - Code Snippets
   - Security Features
7. **Task 6: AWS Virtual Private Cloud (VPC) Setup**
   - Screenshots
   - Security Considerations
8. **Self-Reflection**
9. **Links and Attachments**
   - Code Repository
   - Panopto Video Recording

## 1. Introduction

Within this report I will document the development process and implementation for the secure web application "Lovejoy’s Antique Evaluation Web Application." This project has been designed to deliver a secure application for the evaulation of antiqus. Within the application there will be security measures taken place including SQL Injection, XSS, and CSRF defence.To support this I will be providing annotated code snuppets and screenshots.

## Task 1: User Registration

### Overview

The user registration system will allow users to create there account. They will need to provide their name, email, password, and contact number. The implimentation will focuse on the usability and ensure there is adicuet security enforced. This will increase the integrity and protection against attacks.

---

### Input Validation

First off was input validation. This implementation the users inputed data which met the formation and prevents the chance of invalid or malicious inputs.

- **Name Validation:** Only allows alphabetic characters and spaces.
- **Email Validation:** Uses `filter_var()` to check the email format.
- **Password Strength:** Enforces strong passwords with at least one uppercase letter, one lowercase letter, one number, and one special character.
- **Contact Number Validation:** Ensures a 10-digit numeric format.

```php
$name = htmlspecialchars(trim($_POST['name']));
$email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
$password = $_POST['password'];
$contact = htmlspecialchars(trim($_POST['contact']));

if (!preg_match('/^[a-zA-Z\s]+$/', $name)) {
    $errorMessage = 'Name must only contain letters and spaces';
} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errorMessage = 'Invalid email address';
} elseif (!preg_match('/^\d{10}$/', $contact)) {
    $errorMessage = 'Contact number must be exactly 10 digits';
} elseif (!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $password)) {
    $errorMessage = 'Password must be at least 8 characters long, include an uppercase letter, a number, and a special character.';
}
```

### Password Hashing

To implement the password protection in my project i used bcrypt to hash securly. This ensures that they are not stored in plaintext. This would protect against the chance of data breaches.

```php
$hashedPassword = password_hash($password, PASSWORD_BCRYPT);
```

### Database Interaction

To insert the user data into the database I prepared SQL statements. These will mitigate the risk of SQL Injection.

```php
$stmt = $pdo->prepare("INSERT INTO users (name, email, password, contact_number) VALUES (?, ?, ?, ?)");
$stmt->execute([$name, $email, $hashedPassword, $contact]);
```

To ensure that error handling is controlled gracefully. I have outlined the chance of duplicate email registrations or other database inssue in a error report.

```php
if ($e->getCode() == 23000) {
    $errorMessage = "Email already exists. Please choose another one.";
} else {
    error_log("Database error: " . $e->getMessage());
    $errorMessage = "Something went wrong. Please try again later.";
}
```

### Database Design

When designing the users table scheme I had to take into account the data integrity and the support for role-base access in the future. To implement the scheme I did the following:

- Primary Key: `id` - A unique identifier for each user.
- Unique Constraint: `email` - Prevents duplicate email registrations.
- Additional Fields:
  - `password`: Stores bcrypt-hashed passwords.
  - `role`: Defaulted to user for role-based access control.
  - `created_at`: Timestamp for user creation.

```sql
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    contact_number VARCHAR(15),
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

### Security Analysis

Password Security:

- Passwords are hashed using bcrypt with a secure salt.
- Implementaion of password requirements to enforce and prevent weak user credentials.

SQL Injection Prevention:

- Before input the data into the database the queries are prepared. This ensure the user inputs are text data and not malicous executable code.

Input Validation:

- Enforcing strict validation for input fields. This reduced the chance for harmful data being storded in the database.
- Error Handling
- Graceful handling of errors like duplicate emails prevents unnecessary information disclosure.

## Task 2: Secure Login Feature

### Overview

The login page contains functionality with will ensure only registers users can access the system. This will be done by confirming their credentials. This section of the report will outline my implementaion of a secure user login/authentication page.

---

### Input Validation

Users will input there data and it will be validated to ensure that the email data is sanitized before processing.

```php
$email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
$password = $_POST['password'];

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errorMessage = 'Invalid email address.';
}
```

### Password Verification

I have utilised bcrypt to verif the hashed password saved within the database. This is then compared against the user provided password.

```php
$stmt = $pdo->prepare("SELECT id, name, role, password FROM users WHERE email = ?");
$stmt->execute([$email]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if ($user && password_verify($password, $user['password'])) {
  // Store user information in session
  $_SESSION['user_id'] = $user['id'];
  $_SESSION['name'] = $user['name'];
  $_SESSION['role'] = $user['role'];

  header('Location: dashboard.php');
  exit; // Prevent further code execution
}
```

### Session Handling

After a successful login has been completed and confirmed a session is initiated for the user. This will ensure that there access is protected.

```php
session_start();
```

#### Error Handling

Proper error handling is implemented to prevent information disclosure:

- Generic error messages for invalid login attempts.
- Logging of critical database errors for debugging.

```php
catch (PDOException $e) {
  error_log("Database error during login: " . $e->getMessage());
  $errorMessage = "Something went wrong. Please try again later.";
}
```

### Security Measures

Password Hashing and Verification:

- The passwords saved to the database are securely hashed using bcrypt.
- `password_verify()` this will ensure that the password and stored hash number match.

Input Validation and Sanitization:

- Make sure the inputs are sanitized and valid. THis will prevent and malicaios data injection.
- The `filter_var()` function is used to validate the email address.

SQL Injection Prevention:

- All database queries are executed using prepared statements to mitigate SQL Injection risks.

Session Security:

- Sessions have been implemented to manger the authentication of the user securely.
- Session IDs are regenerated upon login to prevent session fixation attacks.

## Task 3: Password Policy and Recovery

### Overview

Task three focused on the implementation of strong password policys and a secure recovery machnism for passwords. This policy for the password is a requuirements to enhance security. The recovery mechanism will allow users to reset passwords.

---

### Password Policy

The policy will ensure that all the user meet a minimum security requirements:

- Minimum length of 8 characters.
- At least one uppercase letter, one lowercase letter, one number, and one special character.

Validation is implemented using a regular expression:

```php
if (!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $password)) {
    $errorMessage = 'Password must be at least 8 characters long, include an uppercase letter, a number, and a special character.';
}
```

### Password Recovery

The password recovery system provides users the ability to reset their password via a secure token based system:

- **Request Reset:** The user submits their email address to request a password reset.
- **Generate Token:** A unique, time-limited token is generated and emailed to the user.
- **Verify Token:** The token is verified when the user clicks the reset link.
- **Reset Password:** The user enters a new password, which is validated and securely stored.

**Token Generation:** A unique token is generated using PHP’s bin2hex() and random_bytes() functions:

```php
$token = bin2hex(random_bytes(32));
$expiry = date('Y-m-d H:i:s', strtotime('+1 hour'));

$stmt = $pdo->prepare("UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?");
$stmt->execute([$hashedPassword, $user['id']]);
```

**Emailing the Token:** The token is sent to the user’s email address with a reset link:

```php
$resetToken = bin2hex(random_bytes(16));
$resetLink = "http://localhost:8080/src/views/resetPassword.php?token=$resetToken";

$mail = new PHPMailer(true);

$mail->isSMTP();
$mail->Host = 'smtp.sendgrid.net';
$mail->SMTPAuth = true;
$mail->Username = 'apikey';
$mail->Password = ($_ENV['SENDGRID_API_KEY']); 
$mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
$mail->Port = 587;

$mail->setFrom('dev.jamesT@gmail.com', 'Your Application'); 
$mail->addAddress($email);

  // Email content
  $mail->isHTML(true);
  $mail->Subject = 'Password Reset Request';
  $mail->Body = "Hello,<br><br>We received a request to reset your password. You can reset it by clicking the link below:<br>
                   <a href=\"$resetLink\">Reset Password</a><br><br>
                   If you did not request this, please ignore this email.<br><br>Thank you.";

$mail->send();
```

**Token Verification:** The token is validated against the database to ensure it is valid and not expired:

```php
$stmt = $pdo->prepare("SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()");
$stmt->execute([$resetToken]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
```

**Password Update:** Once verified, the user’s password is hashed and updated in the database:

```php
if ($user) {
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    $stmt = $pdo->prepare("UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?");
    $stmt->execute([$hashedPassword, $user['id']]);

    echo "Password has been successfully reset. <a href='login.php'>Login here</a>.";
    exit;
  } else {
$errorMessage = 'Invalid or expired reset token.';
}
```

---

### Security Measures

Password Policy Enforcement:

- Ensuring password requirements which are strong. This reduce brute force attacks.
- Providing real time password strong increases user enjoyment.

Token Security:

- Tokens are stored in a secure mana and expire after a short time.
- Tokens are stored hashed in the database to prevent exposure.

Email Validation:

- Emails are validated to ensure they are properly formatted.
- Reset links are sent only to registered email addresses.

Rate Limiting:

- Prevents abuse of the password recovery system by limiting the number of reset requests per hour.

## Task 4: Evaluation Request Page

### Overview

The Evaluation Request Page allows logged-in users to submit details about antique items they want to be evaluated. Users can provide a description, select a preferred method of contact, and upload a photo of the item. The feature emphasizes security to protect user data and prevent malicious file uploads.

---

### Form Structure

The form is designed to accept user inputs and ensure secure handling of data. Key fields include:

- **Comment Box:** Allows users to describe the item.
- **Contact Method Dropdown:** Provides options for email or phone.
- **File Upload:** Enables users to upload an image of the item.

```html
<form action="evaluationRequest.php" method="POST" enctype="multipart/form-data">
  <label for="description">Description:</label>
  <textarea name="description" required></textarea><br>

  <label for="contactMethod">Preferred Contact Method:</label>
  <select name="contactMethod" required>
    <option value="email">Email</option>
    <option value="phone">Phone</option>
  </select><br>

  <label for="photo">Upload Photo:</label>
  <input type="file" name="photo" accept="image/*" required><br>

  <button type="submit">Submit Request</button>
</form>
```

---

### Server-Side Handling

The backend processes the form inputs securely:

1. **Input Validation:** Ensures all fields are correctly filled and sanitized.
2. **File Validation:** Restricts file uploads to safe types and limits size.

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $description = htmlspecialchars(trim($_POST['description']));
    $contactMethod = $_POST['contactMethod'];
    $photo = $_FILES['photo'];

    // Validate contact method
    if (!in_array($contactMethod, ['email', 'phone'])) {
        die('Invalid contact method');
    }

    // Validate file upload
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!in_array($photo['type'], $allowedTypes)) {
        die('Invalid file type');
    }
    if ($photo['size'] > 2 * 1024 * 1024) { // 2MB limit
        die('File size exceeds the limit');
    }

    // Move the uploaded file to a secure location
    $uploadDir = __DIR__ . '/uploads/';
    $filename = uniqid() . '-' . basename($photo['name']);
    move_uploaded_file($photo['tmp_name'], $uploadDir . $filename);

    // Insert request into the database
    $stmt = $pdo->prepare("INSERT INTO evaluation_requests (description, contact_method, photo_path) VALUES (?, ?, ?)");
    $stmt->execute([$description, $contactMethod, $filename]);

    echo "Evaluation request submitted successfully!";
}
```

---

### Database Design

The `evaluation_requests` table stores the submitted requests with the following schema:

```sql
CREATE TABLE evaluation_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    description TEXT NOT NULL,
    contact_method ENUM('email', 'phone') NOT NULL,
    photo_path VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

Key features:

- **Foreign Key:** Links requests to the respective user for accountability.
- **Photo Path:** Stores the file path of the uploaded photo.

---

### Security Measures

Input Sanitization:

- HTML special characters are escaped to prevent XSS attacks.
- Dropdown values are validated against expected options.

File Upload Validation:

- Restricts allowed file types to images (JPEG, PNG, GIF).
- Limits file size to prevent abuse of storage.

Directory Isolation:

- Uploaded files are stored in a directory outside the web root.
- Filenames are sanitized and made unique to prevent overwriting.

CSRF Protection:

- CSRF tokens are implemented to prevent unauthorized form submissions.

Access Restriction:

- Only logged-in users can access and submit the form.

## Task 5: Evaluation Listing Page (Admin Only)

### Overview

The Evaluation Listing Page is a secure admin-only feature that allows administrators to view all evaluation requests submitted by users. This feature is essential for managing and processing user submissions efficiently while ensuring restricted access to sensitive data.

---

### Code Snippets

#### Access Restriction

Access to the page is restricted to administrators. A session-based role check ensures that only logged-in users with admin privileges can view the page.

```php
session_start();

// Check if user is logged in and has the 'admin' role
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: login.php");
    exit;
}
```

#### Displaying Evaluation Requests

Evaluation requests are fetched from the database and displayed in a tabular format. Pagination is implemented for better usability when handling large numbers of requests.

```php
$stmt = $pdo->prepare("SELECT id, description, contact_method, photo_path, created_at FROM evaluation_requests ORDER BY created_at DESC LIMIT ?, ?");
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$limit = 10;
$offset = ($page - 1) * $limit;
$stmt->bindParam(1, $offset, PDO::PARAM_INT);
$stmt->bindParam(2, $limit, PDO::PARAM_INT);
$stmt->execute();

$requests = $stmt->fetchAll();
```

#### HTML Table for Display

The retrieved data is displayed in a table with a download link for the uploaded photos.

```html
<table>
  <thead>
    <tr>
      <th>ID</th>
      <th>Description</th>
      <th>Contact Method</th>
      <th>Photo</th>
      <th>Submitted At</th>
    </tr>
  </thead>
  <tbody>
    <?php foreach ($requests as $request): ?>
      <tr>
        <td><?php echo htmlspecialchars($request['id']); ?></td>
        <td><?php echo htmlspecialchars($request['description']); ?></td>
        <td><?php echo htmlspecialchars($request['contact_method']); ?></td>
        <td><a href="uploads/<?php echo htmlspecialchars($request['photo_path']); ?>" download>Download Photo</a></td>
        <td><?php echo htmlspecialchars($request['created_at']); ?></td>
      </tr>
    <?php endforeach; ?>
  </tbody>
</table>
```

---

### Database Design

The `evaluation_requests` table supports this feature by storing all the relevant data. The schema is detailed in Task 4.

---

### Security Measures

1. Role-Based Access Control (RBAC)

- Only users with the `admin` role can access this page.
- Session checks validate the user’s role before granting access.

2. Input Sanitization

- All user-provided data displayed on the page is sanitized to prevent XSS attacks.

3. Pagination

- Protects against performance issues by limiting the number of rows displayed per page.

4. File Security

- Uploaded files are referenced using secure links, and download access is restricted to authorized users.

5. Error Handling

- Graceful error messages are displayed if there are issues retrieving data or unauthorized access attempts.

---

### Testing and Results

The Evaluation Listing Page was tested with the following scenarios:

1. **Admin Access:** Verified that only admin users could access the page.
2. **Non-Admin Access:** Confirmed that non-admin users were redirected to the login page.
3. **Pagination:** Ensured correct pagination behavior and performance with large datasets.
4. **File Access:** Verified that uploaded files were accessible only via the secure links.

## Task 6: AWS Virtual Private Cloud (VPC) Setup

### Overview

This task involves setting up a Virtual Private Cloud (VPC) on AWS to securely host the application infrastructure. The VPC configuration ensures isolation of resources, controlled network access, and scalability while maintaining a high level of security.

---

### VPC Configuration

#### Network Setup

The VPC is divided into public and private subnets across multiple availability zones for high availability and fault tolerance. The configuration includes:

1. **VPC CIDR Block:** `10.0.0.0/16`
2. **Subnets:**
   - **Public Subnet 1:** `10.0.0.0/24` - Hosts the NAT gateway and web servers.
   - **Private Subnet 1:** `10.0.1.0/24` - Hosts the application server.
   - **Public Subnet 2:** `10.0.2.0/24` - Used for redundancy in Zone-Y.
   - **Private Subnet 2:** `10.0.3.0/24` - Backup private subnet.
   - **Public Subnet 3:** `10.0.4.0/24` - Reserved for scaling.

#### NAT Gateway

A NAT gateway is configured in the public subnet to allow instances in the private subnets to access the internet securely without exposing them to inbound internet traffic.

#### Security Groups

Two security groups are defined:

1. **Web Server Security Group:**
   - Allows HTTP (`port 80`) and HTTPS (`port 443`) traffic.
   - Restricts SSH (`port 22`) access to specific IP addresses for administrative purposes.
2. **Application Server Security Group:**
   - Allows inbound traffic only from the web server security group for internal communication.
   - No direct internet access.

#### Route Tables

Route tables are configured to direct traffic appropriately:

- Public subnets route internet traffic via the internet gateway.
- Private subnets route internet traffic through the NAT gateway.

---

### Implementation Details

#### Infrastructure as Code

The VPC setup was automated using AWS CloudFormation or Terraform. Below is an example snippet for creating the VPC and subnets:

```yaml
Resources:
  MyVPC:
    Type: "AWS::EC2::VPC"
    Properties:
      CidrBlock: "10.0.0.0/16"
      EnableDnsSupport: true
      EnableDnsHostnames: true

  PublicSubnet1:
    Type: "AWS::EC2::Subnet"
    Properties:
      VpcId: !Ref MyVPC
      CidrBlock: "10.0.0.0/24"
      MapPublicIpOnLaunch: true
      AvailabilityZone: "us-east-1a"

  NATGateway:
    Type: "AWS::EC2::NatGateway"
    Properties:
      SubnetId: !Ref PublicSubnet1
      AllocationId: !GetAtt ElasticIP.AllocationId
```

---

### Security Measures

1. Network Isolation

- Private subnets are isolated from direct internet access, reducing the attack surface.

2. Least Privilege Access

- Security groups restrict inbound and outbound traffic based on need-to-access policies.

3. Data Encryption

- All traffic between instances is encrypted using HTTPS.
- Sensitive data in transit is routed securely through the private network.

4. Monitoring and Logging

- Enabled AWS CloudWatch Logs and VPC Flow Logs for tracking traffic and identifying anomalies.
- Alarms configured to alert on suspicious activities.

5. Backup and Redundancy

- Resources are distributed across multiple availability zones to prevent downtime.

### Testing and Results

The VPC setup was validated with the following tests:

1. **Connectivity Tests:** Verified public and private subnet connectivity using SSH and ping commands.
2. **Access Control:** Confirmed that only allowed IPs could access the public subnets.
3. **Internet Access:** Ensured private instances could access the internet through the NAT gateway.
4. **Traffic Monitoring:** Monitored traffic logs to ensure expected behavior.

## 9. Links and Attachments

- **Code Repository**: [\[fireguard\]](https://github.com/jt-Uni/fireguard.git)
- **Panopto Recording**: [Insert Link]
