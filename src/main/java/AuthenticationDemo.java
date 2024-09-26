import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;

public class AuthenticationDemo {

    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final int SESSION_EXPIRATION_TIME = 3600; // in seconds
    private static Map<String, User> users = new HashMap<>();
    private static Map<String, Integer> failedAttempts = new HashMap<>();
    private static Map<String, Long> sessionExpiration = new HashMap<>();

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Reset Password");
            System.out.println("4. Exit");
            System.out.print("Choose an option: ");
            int option = scanner.nextInt();
            scanner.nextLine();

            switch (option) {
                case 1:
                    System.out.print("Enter username: ");
                    String username = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String password = scanner.nextLine();
                    register(username, password);
                    break;
                case 2:
                    System.out.print("Enter username: ");
                    String loginUsername = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String loginPassword = scanner.nextLine();
                    login(loginUsername, loginPassword);
                    break;
                case 3:
                    System.out.print("Enter username: ");
                    String resetUsername = scanner.nextLine();
                    System.out.print("Enter new password: ");
                    String newPassword = scanner.nextLine();
                    resetPassword(resetUsername, newPassword);
                    break;
                case 4:
                    System.out.println("Exiting...");
                    scanner.close();
                    return;
                default:
                    System.out.println("Invalid option. Try again.");
            }
        }
    }

    private static void register(String username, String password) {
        if (isValidPassword(password)) {
            users.put(username, new User(username, hashPassword(password)));
            System.out.println("User registered successfully.");
        } else {
            System.out.println("Password does not meet security criteria.");
        }
    }

    private static void login(String username, String password) {
        if (failedAttempts.getOrDefault(username, 0) >= MAX_FAILED_ATTEMPTS) {
            System.out.println("Account locked. Too many failed attempts. Try again later.");
            return;
        }

        User user = users.get(username);
        if (user != null && user.password.equals(hashPassword(password))) {
            System.out.println("Login successful.");
            String sessionId = generateSessionId();
            sessionExpiration.put(sessionId, System.currentTimeMillis() / 1000 + SESSION_EXPIRATION_TIME);
            System.out.println("Session created: " + sessionId);
            failedAttempts.put(username, 0);
        } else {
            failedAttempts.put(username, failedAttempts.getOrDefault(username, 0) + 1);
            System.out.println("Invalid credentials. Attempt " + failedAttempts.get(username) + "/" + MAX_FAILED_ATTEMPTS);
        }
    }

    private static void resetPassword(String username, String newPassword) {
        if (isValidPassword(newPassword)) {
            User user = users.get(username);
            if (user != null) {
                user.password = hashPassword(newPassword);
                System.out.println("Password reset successfully.");
            } else {
                System.out.println("User not found.");
            }
        } else {
            System.out.println("New password does not meet security criteria.");
        }
    }

    private static boolean isValidPassword(String password) {
        return password.length() >= 12 &&
                Pattern.compile("[A-Za-z]").matcher(password).find() &&
                Pattern.compile("[0-9]").matcher(password).find() &&
                Pattern.compile("[!@#$%^&*(),.?\":{}|<>]").matcher(password).find();
    }

    private static String hashPassword(String password) {
        return Integer.toString(password.hashCode());
    }

    private static String generateSessionId() {
            SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[24];
            random.nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        }

    // User Class
//    private static class User {
//        String username;
//        String password;
//
//        User(String username, String password) {
//            this.username = username;
//            this.password = password;
//        }
//    }
}
