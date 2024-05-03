package com.securehub.securemedfileshub;

public class User {
    private String username;
    private String salt;
    private String hashedPassword;

    public User(String username, String salt, String hashedPassword) {
        this.username = username;
        this.salt = salt;
        this.hashedPassword = hashedPassword;
    }

    public String getUsername() {
        return username;
    }

    public String getSalt() {
        return salt;
    }

    public String getHashedPassword() {
        return hashedPassword;
    }

    @Override
    public String toString() {
        return username + ";" + salt + ";" + hashedPassword;
    }
}