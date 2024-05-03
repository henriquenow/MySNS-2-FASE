package com.securehub.securemedfileshub;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.file.StandardCopyOption;

public class UserManager {
    private static final String USERS_FILE = "users.txt";
    private static final String MAC_FILE = "admin.mac";
    private Map<String, User> users;

    public UserManager() {
        users = new HashMap<>();
        setup();
    }

    public boolean setup() {
        try {
            Path usersFilePath = Paths.get(USERS_FILE);
            if (!Files.exists(usersFilePath)) {
                createAdminUser();
            }
            loadUsers();

            if (!macFileExists()) {
                System.out.println("MAC file doesn't exist!");
                try (Scanner scanner = new Scanner(System.in)) {
                    System.out.print("Do you want to calculate the MAC for the users file? (yes/no): ");
                    String answer = scanner.nextLine().trim().toLowerCase();
                  
                    while (!answer.equals("yes") && !answer.equals("no") && !answer.equals("y") && !answer.equals("n")) {
                        System.out.print("Invalid answer. Do you want to calculate the MAC for the users file? (yes/no): ");
                        answer = scanner.nextLine().trim().toLowerCase();
                    }
                    if (answer.equals("yes") || answer.equals("y")) {
                        System.out.print("Enter the admin password: ");
                        String adminPassword = scanner.nextLine();
                        updateAdminMac(adminPassword);
                        System.out.println("MAC calculated and stored successfully.");
                    } else {
                        System.out.println("Exiting the server.");
                        return false;
                    }
                }
            }

            if (!verifyUsersMac()) {
                System.out.println("FILE MIGHT BEEN TAMPERED WITH! Exiting the server: MAC verification failed. ");
                return false;
            }

           

          
            return true;
        } catch (IOException e) {
            System.out.println("Error setting up the server: " + e.getMessage());
            return false;
        }
    }

    public void createUser(String username, byte[] salt, byte[] hashedPassword, Path certificateFile) throws IOException {
        System.out.println("Maybe Creating user: " + username);
        if (users.containsKey(username)) {
            throw new IllegalArgumentException("User already exists: " + username);
        }
        System.out.println("User doesn't exist! Creating user: " + username);

        String saltString = Base64.getEncoder().encodeToString(salt);
        String hashedPasswordString = Base64.getEncoder().encodeToString(hashedPassword);

        User user = new User(username, saltString, hashedPasswordString);
        users.put(username, user);

        saveUser(user);
        saveCertificate(username, certificateFile);
    }

    public boolean userExists(String username) {
        return users.containsKey(username);
    }

    public boolean authenticateUser(String username, byte[] providedHashedPassword) {
        User user = users.get(username);
        System.out.println("Auth: User: " + user);
        if (user != null) {
            String storedHashedPassword = user.getHashedPassword();
            return storedHashedPassword.equals(Base64.getEncoder().encodeToString(providedHashedPassword));
        }
        return false;
    }

    private void loadUsers() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(USERS_FILE));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(";");
                if (parts.length == 3) {
                    String username = parts[0];
                    String salt = parts[1];
                    String hashedPassword = parts[2];
                    User user = new User(username, salt, hashedPassword);
                    users.put(username, user);
                }
            }
            reader.close();
        } catch (IOException e) {
            throw new RuntimeException("Error loading users: " + e.getMessage());
        }
    }

    private void createAdminUser() {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.print("Enter password for the 'admin' user: ");
            String adminPassword = scanner.nextLine();

            String salt = generateSalt();
            String hashedPassword = hashPassword(adminPassword, salt);

            User adminUser = new User("admin", salt, hashedPassword);
            users.put("admin", adminUser);

            try {
                saveUser(adminUser);
            } catch (IOException e) {
                throw new RuntimeException("Error saving admin user: " + e.getMessage());
            }
        }
    }

    private void saveUser(User user) throws IOException {
        Path usersFilePath = Paths.get(USERS_FILE);
        if (!Files.exists(usersFilePath)) {
            Files.createFile(usersFilePath);
        }
        String userLine = user.toString() + System.lineSeparator();
        Files.write(usersFilePath, userLine.getBytes(), StandardOpenOption.APPEND);
    }

    private void saveCertificate(String username, Path certificateFile) throws IOException {
        Path certificateDir = Paths.get("certificates");
        Files.createDirectories(certificateDir);
        Path destinationFile = certificateDir.resolve(username + ".cer");
        Files.copy(certificateFile, destinationFile, StandardCopyOption.REPLACE_EXISTING);
    }

    boolean macFileExists() {
        return Files.exists(Paths.get(MAC_FILE));
    }

    boolean verifyUsersMac() throws IOException {
        Path macFilePath = Paths.get(MAC_FILE);
        if (!Files.exists(macFilePath)) {
            System.out.println("Warning: MAC file does not exist.");
            return false;
        }
        String storedMac = new String(Files.readAllBytes(macFilePath)).trim();
        String currentMac = calculateUsersMac();
        return storedMac.equals(currentMac);
    }

    void updateAdminMac(String adminPassword) throws IOException {
        User adminUser = users.get("admin");
        if (adminUser == null) {
            throw new RuntimeException("Admin user not found.");
        }

        String hashedPassword = hashPassword(adminPassword, adminUser.getSalt());
        if (!hashedPassword.equals(adminUser.getHashedPassword())) {
            throw new IllegalArgumentException("Invalid admin password.");
        }

        String currentMac = calculateUsersMac();
        Files.write(Paths.get(MAC_FILE), currentMac.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private String calculateUsersMac() throws IOException {
        try {
            User adminUser = users.get("admin");
            if (adminUser == null) {
                throw new RuntimeException("Admin user not found.");
            }

            byte[] adminPasswordBytes = adminUser.getHashedPassword().getBytes();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] macKeyBytes = md.digest(adminPasswordBytes);
            SecretKeySpec macKey = new SecretKeySpec(macKeyBytes, "HmacSHA256");

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(macKey);
            byte[] usersBytes = Files.readAllBytes(Paths.get(USERS_FILE));
            byte[] macBytes = mac.doFinal(usersBytes);
            return Base64.getEncoder().encodeToString(macBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Error calculating users MAC: " + e.getMessage());
        }
    }

    private static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    private static String hashPassword(String password, String salt) {
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 10000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedBytes = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error hashing password: " + e.getMessage());
        }
    }

    public User getUser(String username) {
        return users.get(username);
    }
}