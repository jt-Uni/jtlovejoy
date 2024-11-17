<?php
use PHPUnit\Framework\TestCase;

class registerTest extends TestCase
{
    // Mock the PDO connection
    protected function setUp(): void
    {
        // Mock session if necessary
        $_SESSION = [];
    }

    public function testInvalidEmail()
    {
        // Simulate POST data with an invalid email
        $_POST = [
            'name' => 'John Doe',
            'email' => 'invalid-email',
            'password' => 'password123',
            'contact' => '1234567890',
        ];

        ob_start();
        require __DIR__ . '/../../src/controllers/registerController.php';
        $output = ob_get_clean();

        // Check if the error message is set for invalid email
        $this->assertStringContainsString('Invalid email address', $output);
    }

    public function testShortPassword()
    {
        // Simulate POST data with a short password
        $_POST = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'short',
            'contact' => '1234567890',
        ];

        ob_start();
        require __DIR__ . '/../../src/controllers/registerController.php';
        $output = ob_get_clean();

        // Check if the error message is set for short password
        $this->assertStringContainsString('Password must be at least 8 characters', $output);
    }

    public function testInvalidContactNumber()
    {
        // Simulate POST data with an invalid contact number
        $_POST = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'contact' => 'invalid-contact',
        ];

        ob_start();
        require __DIR__ . '/../../src/controllers/registerController.php';
        $output = ob_get_clean();

        // Check if the error message is set for invalid contact number
        $this->assertStringContainsString('Invalid contact number', $output);
    }

    public function testSuccessfulRegistration()
    {
        // Simulate valid POST data
        $_POST = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'contact' => '1234567890',
        ];

        // Mock the PDO object
        $pdoMock = $this->createMock(PDO::class);
        $stmtMock = $this->createMock(PDOStatement::class);

        // Set up the PDO mock to return true for execute
        $pdoMock->method('prepare')->willReturn($stmtMock);
        $stmtMock->method('execute')->willReturn(true);

        // Ensure that the script would redirect to the login page after successful registration
        ob_start();
        require __DIR__ . '/../../src/controllers/registerController.php';
        $output = ob_get_clean();

        // Capture headers and check for the redirect
        $headers = headers_list();
        $this->assertContains('Location: login.php', $headers);
    }

    public function testEmailAlreadyExists()
    {
        // Simulate valid POST data for an existing email
        $_POST = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'contact' => '1234567890',
        ];

        // Mock the PDO object to simulate a duplicate email error (error code 23000)
        $pdoMock = $this->createMock(PDO::class);
        $stmtMock = $this->createMock(PDOStatement::class);

        // Set up the PDO mock to throw a PDOException with the duplicate entry error code
        $pdoMock->method('prepare')->willReturn($stmtMock);
        $stmtMock->method('execute')->willThrowException(new PDOException('Duplicate entry', 23000));

        ob_start();
        require __DIR__ . '/../../src/controllers/registerController.php';
        $output = ob_get_clean();

        // Check if the duplicate email error message is shown
        $this->assertStringContainsString('Email already exists. Please choose another one.', $output);
    }

    public function testGeneralDatabaseError()
    {
        // Simulate valid POST data
        $_POST = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'contact' => '1234567890',
        ];

        // Mock the PDO object to simulate a general database error
        $pdoMock = $this->createMock(PDO::class);
        $stmtMock = $this->createMock(PDOStatement::class);

        // Set up the PDO mock to throw a general PDOException
        $pdoMock->method('prepare')->willReturn($stmtMock);
        $stmtMock->method('execute')->willThrowException(new PDOException('Database error'));

        ob_start();
        require __DIR__ . '/../../src/controllers/registerController.php';
        $output = ob_get_clean();

        // Check if a general error message is shown
        $this->assertStringContainsString('Error: Database error', $output);
    }
}
