import java.sql.*;
import java.security.MessageDigest;

public class UserManager {
    
    static final String DB_URL = "jdbc:mysql://localhost:3306/ossis";
    static final String USER = "root";
    static final String PASS = "password";
    
    // Register new user
    public static boolean registerUser(String username, String email, String password) {
        if (!isValidUsername(username) || !isValidPassword(password)) {
            return false;
        }
        
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
            
            // Check if user exists
            String checkSql = "SELECT id FROM users WHERE username = ?";
            PreparedStatement checkStmt = conn.prepareStatement(checkSql);
            checkStmt.setString(1, username);
            ResultSet rs = checkStmt.executeQuery();
            
            if (rs.next()) {
                conn.close();
                return false; // User already exists
            }
            
            // Insert new user with hashed password
            String insertSql = "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)";
            PreparedStatement insertStmt = conn.prepareStatement(insertSql);
            insertStmt.setString(1, username);
            insertStmt.setString(2, email);
            insertStmt.setString(3, hashPassword(password));
            insertStmt.setString(4, "STUDENT");
            insertStmt.executeUpdate();
            
            conn.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    // Validate username
    static boolean isValidUsername(String username) {
        return username != null && username.matches("^[a-zA-Z0-9]{3,50}$");
    }
    
    // Validate password (at least 8 chars)
    static boolean isValidPassword(String password) {
        return password != null && password.length() >= 8 && password.length() <= 256;
    }
    
    // Hash password SHA-256
    static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes());
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
}
