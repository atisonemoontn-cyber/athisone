<?php
session_start();
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $fullname = filter_input(INPUT_POST, 'fullname', FILTER_SANITIZE_STRING);
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Validate input
    if (empty($fullname) || empty($email) || empty($username) || empty($password)) {
        die("All fields are required");
    }

    if ($password !== $confirm_password) {
        die("Passwords do not match");
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Invalid email format");
    }

    try {
        // Check if email or username already exists
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ? OR username = ?");
        $stmt->execute([$email, $username]);
        if ($stmt->fetchColumn() > 0) {
            die("Email or username already exists");
        }

        // Hash password
        $password_hash = password_hash($password, PASSWORD_DEFAULT);

        // Insert new user
        $stmt = $pdo->prepare("INSERT INTO users (fullname, email, username, password_hash) VALUES (?, ?, ?, ?)");
        $stmt->execute([$fullname, $email, $username, $password_hash]);

        // Redirect to login page
        header("Location: login.html");
        exit();
    } catch(PDOException $e) {
        die("Registration failed: " . $e->getMessage());
    }
}
?>