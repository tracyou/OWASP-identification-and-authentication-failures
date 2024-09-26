import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class NotSecureAuthenticationDemo {

    private static Map<String, String> users = new HashMap<>();
    private static Map<String, String> sessions = new HashMap<>();

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
        users.put(username, password);
        System.out.println("User registered successfully.");
    }

    private static void login(String username, String password) {
        String storedPassword = users.get(username);
        if (storedPassword != null && storedPassword.equals(password)) {
            String sessionId = generateSessionId();
            sessions.put(sessionId, username);
            System.out.println("Login successful. Session ID: " + sessionId);
        } else {
            System.out.println("Invalid credentials.");
        }
    }

    private static void resetPassword(String username, String newPassword) {
        if (users.containsKey(username)) {
            users.put(username, newPassword);
            System.out.println("Password reset successfully.");
        } else {
            System.out.println("User not found.");
        }
    }

    private static String generateSessionId() {
        return Long.toString(System.currentTimeMillis());
    }
}
