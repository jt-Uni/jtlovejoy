document.addEventListener("DOMContentLoaded", function () {
  const passwordInput = document.getElementById("password");
  const strengthBar = document.getElementById("strength-bar");
  const strengthText = document.getElementById("strength-text");

  passwordInput.addEventListener("input", function () {
      const password = passwordInput.value;
      const strength = checkPasswordStrength(password);

      strengthBar.style.width = strength.percentage + "%";
      strengthBar.style.backgroundColor = strength.color;
      strengthText.textContent = strength.message;
  });
});

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
