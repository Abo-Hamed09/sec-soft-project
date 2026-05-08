import java.sql.*;
import java.security.MessageDigest;
import java.util.Scanner;

public class LoginSystem {
    
    static final String DB_URL = "jdbc:mysql://localhost:3306/ossis";
    static final String USER = "root";
    static final String PASS = "password";
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== OSSIS Secure Login ===");
        System.out.print("Username: ");
        String username = scanner.nextLine();
        
        System.out.print("Password: ");
        String password = scanner.nextLine();
        
        // Validate input
        if (!isValidUsername(username)) {
            System.out.println("Error: Invalid credentials");
            return;
        }
        
        // Authenticate user
        if (authenticate(username, password)) {
            System.out.println("Login successful!");
            System.out.println("Welcome, " + username);
        } else {
            System.out.println("Error: Invalid credentials");
        }
        
        scanner.close();
    }
    
    // Input validation - prevent injection
    static boolean isValidUsername(String username) {
        if (username == null || username.isEmpty()) {
            return false;
        }
        return username.matches("^[a-zA-Z0-9]{3,50}$");
    }
    
    // Authenticate user with SQL injection prevention
    static boolean authenticate(String username, String password) {
        try {
            // Load MySQL driver
            Class.forName("com.mysql.cj.jdbc.Driver");
            
            // Connect to database
            Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
            
            // Use parameterized query (prevents SQL injection)
            String sql = "SELECT password FROM users WHERE username = ?";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, username); // Safe - parameterized
            
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                String hashedPassword = rs.getString("password");
                
                // Hash the entered password
                String enteredHash = hashPassword(password);
                
                // Compare hashes
                if (hashedPassword.equals(enteredHash)) {
                    logLoginAttempt(username, true);
                    conn.close();
                    return true;
                }
            }
            
            logLoginAttempt(username, false);
            conn.close();
            return false;
            
        } catch (Exception e) {
            System.out.println("Error: Invalid credentials");
            return false;
        }
    }
    
    // Hash password using SHA-256
    static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes());
            
            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }
    
    // Log login attempt
    static void logLoginAttempt(String username, boolean success) {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
            
            String sql = "INSERT INTO login_logs (username, success, timestamp) VALUES (?, ?, NOW())";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, username);
            stmt.setBoolean(2, success);
            stmt.executeUpdate();
            
            conn.close();
        } catch (Exception e) {
            // Silently fail - logging issue shouldn't stop login
        }
    }
}
