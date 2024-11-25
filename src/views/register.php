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
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
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

    <script>
        // Function to check password strength
        const passwordInput = document.getElementById("password");
        const strengthBar = document.getElementById("strength-bar");
        const strengthText = document.getElementById("strength-text");

        passwordInput.addEventListener("input", function() {
            const password = passwordInput.value;
            const strength = checkPasswordStrength(password);

            // Update strength bar and text
            strengthBar.style.width = strength.percentage + "%";
            strengthBar.style.backgroundColor = strength.color;
            strengthText.textContent = strength.message;
        });

        // Check password strength
        function checkPasswordStrength(password) {
            let strength = { percentage: 0, message: "Weak", color: "#ff0000" };

            if (password.length >= 8) {
                strength.percentage = 25;
                if (/[A-Z]/.test(password)) {
                    strength.percentage = 50;
                    if (/\d/.test(password)) {
                        strength.percentage = 75;
                        if (/[@$!%*?&]/.test(password)) {
                            strength.percentage = 100;
                            strength.message = "Strong";
                            strength.color = "#4CAF50";
                        } else {
                            strength.message = "Medium";
                            strength.color = "#FFA500";
                        }
                    } else {
                        strength.message = "Medium";
                        strength.color = "#FFA500";
                    }
                } else {
                    strength.message = "Weak";
                    strength.color = "#ff0000";
                }
            } else {
                strength.message = "Weak";
                strength.color = "#ff0000";
            }

            return strength;
        }
    </script>
</body>
</html>
