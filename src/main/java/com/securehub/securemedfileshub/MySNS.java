package com.securehub.securemedfileshub;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Scanner;
import javax.crypto.spec.PBEKeySpec;

import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Arrays;

public class MySNS {
    public static void main(String[] args) {

        System.out.println("Arguments with index:");
        for (int i = 0; i < args.length; i++) {
            System.out.println(i + ": " + args[i]);
        }

        if (args.length < 5) {
            printUsage();
            return;
        }

     
        UserManager userManager = new UserManager();
    
        String serverAddress = args[1].split(":")[0];
        int serverPort = Integer.parseInt(args[1].split(":")[1]);
        String command = null;
        String username = null;
        String password = null;
        String certificateFile = null;
        String doctorUsername = null;
        String patientUsername = null;

        if(args.length==6){ //-au
            command = args[2];
        }else {
            if (args[6].equals("-g")) {
                command = args[6];
            } else {
            command = args[8];
        }
        }
    
    
        System.setProperty("javax.net.ssl.trustStore", "truststore.client");
        System.setProperty("javax.net.ssl.trustStorePassword", "server");
    
        System.out.println("Truststore path: truststore.client");
        System.out.println("Truststore password: server");
    
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = null;
        try {
            System.out.println("Connecting to server: " + serverAddress + ":" + serverPort);
            socket = (SSLSocket) sf.createSocket(serverAddress, serverPort);
            System.out.println("Connected to server.");
    
            // Verify the server's identity
            SSLSession session = socket.getSession();
            X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];
            String subject = cert.getSubjectX500Principal().getName();
            String issuer = cert.getIssuerX500Principal().getName();
    
            System.out.println("Server Subject: " + subject);
            System.out.println("Server Issuer: " + issuer);
    
            // The hostname should be this CN=Server Oficial,OU=SecureFilesHub,O=SecureFilesHub,L=Lisboa,ST=Lisboa,C=PT
            String hostname = "Server Oficial";
            String cn = extractCN(subject);
            if (!hostname.equals(cn)) {
                throw new Exception("Server hostname does not match the certificate CN");
            }
    
            System.out.println("Server identity verified.");
    
            switch (command) {
                case "-au":
                    if (args.length != 6) {
                        System.err.println("Invalid arguments for -au command.");
                        printUsage();
                        return;
                    }
                    username = args[3];
                    password = args[4];
                    certificateFile = args[5];
                    break;
                case "-sc":
                case "-sa":
                case "-se":
                    if (args.length < 9) {
                        System.err.println("Invalid arguments for " + command + " command.");
                        printUsage();
                        return;
                    }
                    doctorUsername = args[3];
                    password = args[5];
                    patientUsername = args[7];
                 
                    break;
                case "-g":
                    if (args.length < 7) {
                        System.err.println("Invalid arguments for -g command.");
                        printUsage();
                        return;
                    }
                    patientUsername = args[3];
                    password = args[5];
                
                    break;
                default:
                    System.err.println("Invalid command: " + command);
                    printUsage();
                    return;
            }
    
            int nOfFilesSent = 0;
            int nOfFilesAlreadyPresent = 0;
            int nOfFilesMissing = 0;
            int nOfFilesReceived = 0;
    
            try (DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                 DataInputStream dis = new DataInputStream(socket.getInputStream())) {
                
                    dos.writeUTF(command); // Send the command
    
                // Process files based on the command
                int numberOfFiles = 0;
                boolean authenticated = false;
                switch (command) {
                    case "-sc":
                    case "-sa":
                    case "-se":
                    //Auth com doctorUsername
                     authenticated =   authenticateUser(dos, dis, doctorUsername, password);
                
                    if (!authenticated) {
                        System.err.println("Authentication failed.");
                        return;
                    }  
                    numberOfFiles = args.length - 9;
                    //See what files don't actually exist in the client so we don't send those!

                    for (int i=0 ;i < numberOfFiles; i++){
                        Path file = Paths.get(args[i+9]);
                        if (!Files.exists(file)) {
                            System.err.println("File not found in the client: " + file);
                            nOfFilesMissing++;
                        }
                    }
                    numberOfFiles = numberOfFiles - nOfFilesMissing;

                    if(numberOfFiles == 0){
                        System.err.println("No files to send found in the client!");
                        return;
                    }

                    System.out.println("Sending number of files: " + numberOfFiles);
                    dos.writeInt(numberOfFiles); // Send the number of files to the server
                    dos.writeUTF(patientUsername);
                    processFiles(args, command, doctorUsername, patientUsername, dos, dis,
                                 nOfFilesSent, nOfFilesAlreadyPresent, nOfFilesMissing);
                    break;
                     //Auth com patient username
                    case "-g":
                     authenticated =   authenticateUser(dos, dis, patientUsername, password);
                
                    if (!authenticated) {
                        System.err.println("Authentication failed.");
                        return;
                    }
                 
                        numberOfFiles = args.length - 7;
                        System.out.println("Receiving number of files: " + numberOfFiles);
                        dos.writeInt(numberOfFiles); // Send the number of files to the server
                        dos.writeUTF(patientUsername);
                        nOfFilesReceived = processGCommand(dis, dos, patientUsername, Arrays.copyOfRange(args, 7, args.length));
                        System.out.println("Operation complete. Number of files received: " + nOfFilesReceived + ".");
                        break;
                    case "-au":
                        System.out.println("Creating user: " + username);
                        createUser(dos, dis, username, password, certificateFile,userManager);
                        return;
                    default:
                        System.err.println("Unknown command: " + command);
                        dos.writeUTF("Error: Unknown command");
                        break;
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }
    
        } catch (Exception e) {
            System.err.println("Error connecting to server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                    System.out.println("Socket closed.");
                } catch (IOException e) {
                    System.err.println("Error closing socket: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    private static boolean authenticateUser(DataOutputStream dos, DataInputStream dis, String username, String password) {
        try {
            // Send the username to the server for authentication

            dos.writeUTF(username);
            dos.flush();
    
            // Receive the salt from the server
            int saltLength = dis.readInt();
            if (saltLength == -1) {
                // User not found
                System.err.println("USER NOT FOUND!");
                return false;
            }
            byte[] salt = new byte[saltLength];
            dis.readFully(salt);
    
            // Hash the password with the received salt using PBKDF2
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
    
            // Send the hashed password to the server for verification
            dos.writeInt(hashedPassword.length);
            dos.write(hashedPassword);
            dos.flush();
    
            // Receive the authentication result from the server
            boolean authResult = dis.readBoolean();

            if (authResult) {
                System.out.println("Authentication successful.");
            } else {
                System.err.println("WRONG PASSWORD! Authentication failed.");
            }


            return authResult ;
        } catch (Exception e) {
            System.err.println("Error during authentication: " + e.getMessage());
            return false;
        }
    }

    
    private static void processFiles(String[] args, String command, String doctorUsername, String patientUsername,
                                 DataOutputStream dos, DataInputStream dis,
                                 int nOfFilesSent, int nOfFilesAlreadyPresent, int nOfFilesMissing) throws Exception {
   
                                    int idxOfFirstFile = 8;

    for (int i = idxOfFirstFile; i < args.length; i++) {
        System.out.println("Processing file: " + args[i]);
        Path file = Paths.get(args[i]);

        if (!Files.exists(file)) {
            System.err.println("Skipping file not found in the client: " + file);
            continue;
        }

        System.out.println("File exists in the client: " + file);

        switch (command) {
            case "-sc":
                processScCommand(file, dos, doctorUsername, patientUsername);
                break;
            case "-sa":
                processSaCommand(file, dos, dis, doctorUsername, patientUsername);
                break;
            case "-se":
                processSeCommand(file, dos, dis, doctorUsername, patientUsername);
                break;
            default:
                System.err.println("Unknown command: " + command);
                dos.writeUTF("Error: Unknown command");
                continue;
        }

        String serverResponse = dis.readUTF();
        System.out.println("Server response after processing command: " + serverResponse);

        if (serverResponse.startsWith("Error:")) {
            nOfFilesAlreadyPresent++;
        } else {
            nOfFilesSent++;
        }
    }

    try {
        String serverFinalResponse = dis.readUTF();
        System.out.println("Server final response: " + serverFinalResponse);
    } catch (EOFException e) {
        System.out.println("All Done");
    }

    System.out.println("Operation complete. " + nOfFilesSent + " files sent, " + nOfFilesAlreadyPresent
            + " files were already present, and " + nOfFilesMissing + " files were missing.");
}
    private static String extractCN(String x500Name) {
    X500Principal principal = new X500Principal(x500Name);
    String cn = principal.getName(X500Principal.RFC2253);
    int start = cn.indexOf("CN=");
    if (start != -1) {
        int end = cn.indexOf(",", start);
        if (end == -1) {
            end = cn.length();
        }
        return cn.substring(start + 3, end);
    }
    return null;
}
    private static void printUsage() {
/* 
    mySNS -a <serverAddress> -m <username do médico> -p <password> -u <username do utente> -sc {<filenames>}+   
    mySNS -a <serverAddress> -m <username do médico> -p <password> -u <username do utente> -sa {<filenames>}+ 
    mySNS -a <serverAddress> -m <username do médico> -p <password> -u <username do utente> -se {<filenames>}+ 
    myCloud -a <serverAddress> -u <username do utente> -p <password> -g {<filenames>}+
        */

                System.out.println("Usage:");
                System.out.println("mySNS -a <serverAddress> -au <username> <password> <certificateFile>");
                System.out.println("mySNS -a <serverAddress> -m <doctorUsername> -p <password> -u <patientUsername> -sc {<filenames>}+");
                System.out.println("mySNS -a <serverAddress> -m <doctorUsername> -p <password> -u <patientUsername> -sa {<filenames>}+");
                System.out.println("mySNS -a <serverAddress> -m <doctorUsername> -p <password> -u <patientUsername> -se {<filenames>}+");
                System.out.println("mySNS -a <serverAddress> -u <patientUsername> -p <password> -g {<filenames>}+");
            
    }

    private static void createUser(DataOutputStream dos, DataInputStream dis, String username, String password,
    String certificateFile, UserManager userManager) {
try {
// Generate a random salt for password hashing
SecureRandom random = new SecureRandom();
byte[] salt = new byte[16];
random.nextBytes(salt);

// Hash the password with the salt using PBKDF2
KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
byte[] hashedPassword = factory.generateSecret(spec).getEncoded();

// Send the username, salt, and hashed password to the server
dos.writeUTF(username);
dos.writeInt(salt.length);
dos.write(salt);
dos.writeInt(hashedPassword.length);
dos.write(hashedPassword);
dos.flush();

// Wait for the server's response
String response = dis.readUTF();
if (response.equals("OK")) {
    // Server approved the user creation, proceed with sending the certificate
    Path certificatePath = Paths.get(certificateFile);
    if (!Files.exists(certificatePath)) {
        System.err.println("Certificate file not found: " + certificateFile);
        return;
    }
    System.out.println("Certificate file found: " + certificateFile);

    byte[] certificateBytes = Files.readAllBytes(certificatePath);
    System.out.println("Sending certificate length: " + certificateBytes.length + " and certificate bytes");
    dos.writeInt(certificateBytes.length);
    dos.write(certificateBytes);
    dos.flush();

    response = dis.readUTF();
    System.out.println(response);
} else {
    System.out.println("User creation failed: " + response);
}
} catch (IOException e) {
    System.err.println("Error creating user: " + e.getMessage());
} catch (NoSuchAlgorithmException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
} catch (InvalidKeySpecException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
}
}

    private static int processGCommand(DataInputStream dis, DataOutputStream dos, String patientUsername,
            String[] filenames) throws IOException {

        int nOfFilesReceived = 0;
        for (String filename : filenames) {
            System.out.println("Requesting file: " + filename);
            dos.writeUTF(filename);
            dos.flush();

            boolean fileExists = dis.readBoolean();
            if (!fileExists) {
                System.out.println("File does not exist on the server: " + filename);
                continue;
            }
            System.out.println("File exists in some form: " + fileExists);
            while (fileExists) {
                String receivedFilename = dis.readUTF();
                System.out.println("Receiving file: " + receivedFilename);
                if (receivedFilename.endsWith(".cifrado")) {
                    receiveEncryptedFileAndDecrypt(dis, patientUsername, receivedFilename);
                    nOfFilesReceived++;
                } else if (receivedFilename.endsWith(".assinado")) {
                    receiveSignedFileAndVerify(dis, patientUsername, receivedFilename);
                    nOfFilesReceived++;
                } else if (receivedFilename.endsWith(".seguro")) {
                    receiveSecureFile(dis, receivedFilename, patientUsername);
                    nOfFilesReceived++;
                }
                fileExists = dis.readBoolean();
            }
        }

        return nOfFilesReceived;
    }

    // Wraps the AES key with the public RSA key
    private static byte[] wrapAESKey(SecretKey aesKey, Certificate cert) throws Exception {
        if (cert == null) {
            System.err.println(
                    "Certificate is null. Check if the correct alias is used and the certificate exists in the KeyStore.");
            return null; // or throw an exception
        }

        PublicKey publicKey = cert.getPublicKey();
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.WRAP_MODE, publicKey);
        return rsaCipher.wrap(aesKey);
    }

    // Generates an AES key
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // Encrypts file bytes with an AES key
    private static byte[] encryptFile(byte[] fileBytes, SecretKey aesKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return aesCipher.doFinal(fileBytes);
    }

    // Encrypts the AES key with the public RSA key
    private static byte[] encryptAESKey(SecretKey aesKey, Certificate cert) throws Exception {
        if (cert == null) {
            System.err.println(
                    "Certificate is null. Check if the correct alias is used and the certificate exists in the KeyStore.");
            return null; // or throw an exception
        }
        PublicKey publicKey = cert.getPublicKey();
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsaCipher.doFinal(aesKey.getEncoded());
    }

    // Client side: MySNS.java
    private static void processSaCommand(Path file, DataOutputStream dos, DataInputStream dis, String doctorUsername,
            String patientUsername) throws Exception {
        KeyStore keystore = getKeyStore(doctorUsername + ".keystore", doctorUsername.toCharArray());
        byte[] fileBytes = Files.readAllBytes(file);
        PrivateKey privateKey = (PrivateKey) keystore.getKey(doctorUsername + "alias", doctorUsername.toCharArray());
        byte[] signatureBytes = signFile(fileBytes, privateKey);

        System.out.println("Sending signed file and signature to the server...");
        // Send the signed file in chunks
        dos.writeUTF(file.getFileName().toString());
        dos.writeLong(fileBytes.length);
        sendFileChunk(dos, fileBytes);

        // Send the signature
        // Signature filename: <filename>.assinatura.<doctorUsername>
        dos.writeUTF(file.getFileName().toString() + ".assinatura." + doctorUsername);
        dos.writeInt(signatureBytes.length);
        dos.write(signatureBytes);

        dos.flush();
    }

    // Signs the file using the patient's private key from the keystore
    private static byte[] signFile(byte[] fileBytes, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(fileBytes);
        return signature.sign();
    }

    private static void processScCommand(Path file, DataOutputStream dos, String doctorUsername, String patientUsername)
            throws Exception {

        try (Scanner scanner = new Scanner(System.in)) {
            KeyStore keystore = getKeyStore(doctorUsername + ".keystore", doctorUsername.toCharArray());
            SecretKey aesKey = generateAESKey();
            System.out.println("Fetching certificate with alias: " + patientUsername + "cert");
            Certificate patientCertificate = keystore.getCertificate(patientUsername + "cert");

            if (patientCertificate == null) {
                // Certificate not found in the keystore
                System.out.println("Certificate not found for alias: " + patientUsername + "cert");

                System.out.println("Do you want to export and import the certificate? (yes/no)");
                String choice = scanner.nextLine().trim().toLowerCase();

                if ("yes".equals(choice)) {
                    try {
                        KeyStore key = getKeyStore(patientUsername + ".keystore", patientUsername.toCharArray());

                        FileInputStream fis = new FileInputStream(patientUsername + ".keystore");
                        key.load(fis, patientUsername.toCharArray());
                        fis.close();

                        // Export the certificate from the source keystore
                        Certificate patientCert = key.getCertificate(patientUsername + "alias");
                        if (patientCert == null) {
                            throw new RuntimeException("Certificate not found in patient keystore.");
                        }

                        // Import the certificate into the current keystore
                        keystore.setCertificateEntry(patientUsername + "cert", patientCert);

                        // Save the updated keystore
                        FileOutputStream fos = new FileOutputStream(doctorUsername + ".keystore");
                        keystore.store(fos, doctorUsername.toCharArray());
                        fos.close();

                        System.out.println("Certificate imported into the keystore successfully.");
                    } catch (Exception e) {
                        e.printStackTrace();
                        // Handle exceptions appropriately
                    }
                } else if ("no".equals(choice)) {
                    System.exit(1);
                    return;

                } else {
                    // Handle the case where the user inputs an invalid choice
                    System.out.println("Invalid choice. Please enter 'yes' or 'no'.");
                    return;
                }
            } else {
                // Certificate retrieved successfully
                System.out.println("Certificate retrieved successfully");
                // Proceed with your logic here, e.g., encrypt file using the retrieved
                // certificate
            }
            patientCertificate = keystore.getCertificate(patientUsername + "cert");

            System.out.println("Certificate retrieved Successfully");
            byte[] wrappedAesKey = wrapAESKey(aesKey, patientCertificate);

            // Encrypt the file
            byte[] encryptedFileBytes = encryptFile(Files.readAllBytes(file), aesKey);

            // Send the encrypted file in chunks
            dos.writeUTF(file.getFileName().toString());
            dos.writeLong(encryptedFileBytes.length);
            sendFileChunk(dos, encryptedFileBytes);

            // Send the wrapped AES key
            dos.writeInt(wrappedAesKey.length);
            dos.write(wrappedAesKey);
        }

        dos.flush();
    }

    private static void processSeCommand(Path file, DataOutputStream dos, DataInputStream dis, String doctorUsername,
            String patientUsername) throws Exception {

        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("Processing -se command...");

            KeyStore keystore = getKeyStore(doctorUsername + ".keystore", doctorUsername.toCharArray());

            SecretKey aesKey = generateAESKey();
            System.out.println("Generated AES key.");

            byte[] fileBytes = Files.readAllBytes(file);
            System.out.println("Read file bytes. Size: " + fileBytes.length);

            byte[] encryptedFileBytes = encryptFile(fileBytes, aesKey);
            System.out.println("Encrypted file bytes. Size: " + encryptedFileBytes.length);

            Certificate patientCertificate = keystore.getCertificate(patientUsername + "cert");

            if (patientCertificate == null) {
                // Certificate not found in the keystore
                System.out.println("Certificate not found for alias: " + patientUsername + "cert");

                System.out.println("Do you want to export and import the certificate? (yes/no)");
                String choice = scanner.nextLine().trim().toLowerCase();

                if ("yes".equals(choice)) {
                    try {
                        KeyStore key = getKeyStore(patientUsername + ".keystore", patientUsername.toCharArray());

                        FileInputStream fis = new FileInputStream(patientUsername + ".keystore");
                        key.load(fis, patientUsername.toCharArray());
                        fis.close();

                        // Export the certificate from the source keystore
                        Certificate patientCert = key.getCertificate(patientUsername + "alias");
                        if (patientCert == null) {
                            throw new RuntimeException("Certificate not found in patient keystore.");
                        }

                        // Import the certificate into the current keystore
                        keystore.setCertificateEntry(patientUsername + "cert", patientCert);

                        // Save the updated keystore
                        FileOutputStream fos = new FileOutputStream(doctorUsername + ".keystore");
                        keystore.store(fos, doctorUsername.toCharArray());
                        fos.close();

                        System.out.println("Certificate imported into the keystore successfully.");
                    } catch (Exception e) {
                        e.printStackTrace();
                        // Handle exceptions appropriately
                    }
                } else if ("no".equals(choice)) {
                    System.exit(1);
                    return;

                } else {
                    // Handle the case where the user inputs an invalid choice
                    System.out.println("Invalid choice. Please enter 'yes' or 'no'.");
                    return;
                }
            } else {
                // Certificate retrieved successfully
                System.out.println("Certificate retrieved successfully");
                // Proceed with your logic here, e.g., encrypt file using the retrieved
                // certificate
            }

            patientCertificate = keystore.getCertificate(patientUsername + "cert");

            byte[] encryptedAesKey = encryptAESKey(aesKey, patientCertificate);
            System.out.println("Encrypted AES key. Size: " + encryptedAesKey.length);

            PrivateKey privateKey = (PrivateKey) keystore.getKey(doctorUsername + "alias", doctorUsername.toCharArray());
            byte[] signatureBytes = signFile(fileBytes, privateKey);
            System.out.println("Signed file. Signature size: " + signatureBytes.length);

            System.out.println("Sending encrypted and signed files to the server...");
            sendEncryptedAndSignedFiles(dos, file.getFileName().toString(), encryptedFileBytes, fileBytes, encryptedAesKey,
                    signatureBytes,
                    doctorUsername, patientUsername);
        }
        System.out.println("Waiting for server response...");
        String serverResponse = dis.readUTF();
        System.out.println("Server response: " + serverResponse);

        dos.flush(); // Flush the DOS to send the file data immediately
    }

    private static void sendEncryptedAndSignedFiles(DataOutputStream dos, String filename, byte[] encryptedFileBytes,
            byte[] fileBytes, byte[] encryptedAesKey, byte[] signatureBytes, String doctorUsername,
            String patientUsername)
            throws IOException {
        // Send encrypted file
        System.out.println("Sending encrypted file: " + filename + ".cifrado");
        dos.writeUTF(filename + ".cifrado");
        dos.writeLong(encryptedFileBytes.length);
        sendFileChunk(dos, encryptedFileBytes);

        // Send secure file
        System.out.println("Sending secure file: " + filename + ".seguro");
        dos.writeUTF(filename + ".seguro");
        dos.writeLong(encryptedFileBytes.length);
        sendFileChunk(dos, encryptedFileBytes);

        // Send encrypted AES key
        System.out.println("Sending encrypted AES key: " + filename + ".chave_secreta." + patientUsername);
        dos.writeUTF(filename + ".chave_secreta." + patientUsername);
        dos.writeInt(encryptedAesKey.length);
        dos.write(encryptedAesKey);

        // Console log filename
        System.out.println("Filename: " + filename);

        System.out.println("Sending signed file: " + filename + ".assinado");
        dos.writeUTF(filename + ".assinado");
        dos.writeLong(fileBytes.length);
        sendFileChunk(dos, fileBytes);

        System.out.println("Sending signature: " + filename + ".assinatura." + doctorUsername);
        dos.writeUTF(filename + ".assinatura." + doctorUsername);
        dos.writeInt(signatureBytes.length);
        dos.write(signatureBytes);
    }

    private static void sendFileChunk(DataOutputStream dos, byte[] fileBytes) throws IOException {
        int offset = 0;
        int chunkSize = 4096;
        while (offset < fileBytes.length) {
            int remainingBytes = fileBytes.length - offset;
            int bytesToSend = Math.min(chunkSize, remainingBytes);
            dos.write(fileBytes, offset, bytesToSend);
            offset += bytesToSend;
        }
    }

    private static void receiveSignedFileAndVerify(DataInputStream dis, String patientUsername, String receivedFilename)
            throws IOException {
        try {
            KeyStore keystore = getKeyStore(patientUsername + ".keystore", patientUsername.toCharArray());

            long signedFileLength = dis.readLong();
            Path tempFile = Files.createTempFile("signed", ".tmp");
            try (OutputStream tempOut = Files.newOutputStream(tempFile)) {
                byte[] buffer = new byte[4096];
                long bytesRead = 0;
                while (bytesRead < signedFileLength) {
                    int bytesToRead = (int) Math.min(buffer.length, signedFileLength - bytesRead);
                    int bytesReceived = dis.read(buffer, 0, bytesToRead);
                    if (bytesReceived == -1) {
                        throw new EOFException("Unexpected end of stream while reading signed file");
                    }
                    tempOut.write(buffer, 0, bytesReceived);
                    bytesRead += bytesReceived;
                }
            }

            // Extract the doctor's username from the signature filename
            String signatureFileName = dis.readUTF();
            System.out.println("Signature filename: " + signatureFileName);
            String doctorUsername = signatureFileName.substring(signatureFileName.lastIndexOf(".") + 1);
            System.out.println("Doctor username: " + doctorUsername);

            int signatureLength = dis.readInt();
            byte[] signatureBytes = new byte[signatureLength];
            dis.readFully(signatureBytes);

            // Retrieve the doctor's certificate from the keystore
            PublicKey publicKey = keystore.getCertificate(doctorUsername + "cert").getPublicKey();

            // Verify the signature
            boolean signatureValid = verifySignature(Files.readAllBytes(tempFile), signatureBytes, publicKey);

            if (signatureValid) {
                // Save the signed file
                String outputFilename = receivedFilename.replace(".assinado", "");
                Path outputFilePath = Paths.get("Client", patientUsername, "Assinados", outputFilename);
                Files.createDirectories(outputFilePath.getParent());
                Files.move(tempFile, outputFilePath, StandardCopyOption.REPLACE_EXISTING);
                System.out.println("File downloaded and signature verified: " + outputFilename);
            } else {
                System.out.println("Signature verification failed for file: " + receivedFilename);
                Files.delete(tempFile);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error occurred while verifying the signature of file: " + receivedFilename);
        }
    }

    private static void receiveSecureFile(DataInputStream dis, String receivedFilename, String patientUsername)
            throws IOException {
        try {
            KeyStore keystore = getKeyStore(patientUsername + ".keystore", patientUsername.toCharArray());

            long encryptedFileLength = dis.readLong();
            Path tempFile = Files.createTempFile("secure", ".tmp");
            try (OutputStream tempOut = Files.newOutputStream(tempFile)) {
                byte[] buffer = new byte[4096];
                long bytesRead = 0;
                while (bytesRead < encryptedFileLength) {
                    int bytesToRead = (int) Math.min(buffer.length, encryptedFileLength - bytesRead);
                    int bytesReceived = dis.read(buffer, 0, bytesToRead);
                    if (bytesReceived == -1) {
                        throw new EOFException("Unexpected end of stream while reading secure file");
                    }
                    tempOut.write(buffer, 0, bytesReceived);
                    bytesRead += bytesReceived;
                }
            }

            int encryptedKeyLength = dis.readInt();
            byte[] encryptedKeyContent = new byte[encryptedKeyLength];
            dis.readFully(encryptedKeyContent);

            // Extract the doctor's username from the signature filename
            String signatureFileName = dis.readUTF();
            System.out.println("Signature filename: " + signatureFileName);
            String doctorUsername = signatureFileName.substring(signatureFileName.lastIndexOf(".") + 1);
            System.out.println("Doctor username: " + doctorUsername);

            int signatureLength = dis.readInt();
            byte[] signatureBytes = new byte[signatureLength];
            dis.readFully(signatureBytes);

            // Decrypt the AES key
            PrivateKey privateKey = (PrivateKey) keystore.getKey(patientUsername + "alias",
                    patientUsername.toCharArray());
            byte[] decryptedKeyBytes = decryptAESKey(encryptedKeyContent, privateKey);
            SecretKey decryptedKey = new SecretKeySpec(decryptedKeyBytes, "AES");

            // Decrypt the file
            byte[] encryptedFileBytes = Files.readAllBytes(tempFile);
            byte[] decryptedFileContent = decryptFile(encryptedFileBytes, decryptedKey);

            // Retrieve the doctor's certificate from the keystore
            PublicKey publicKey = keystore.getCertificate(doctorUsername + "cert").getPublicKey();

            // Verify the signature
            boolean signatureValid = verifySignature(decryptedFileContent, signatureBytes, publicKey);

            if (signatureValid) {
                // Save the decrypted and verified file
                String outputFilename = receivedFilename.replace(".seguro", "");
                Path outputFilePath = Paths.get("Client", patientUsername, "Seguros", outputFilename);
                Files.createDirectories(outputFilePath.getParent());
                Files.write(outputFilePath, decryptedFileContent, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                System.out.println("Secure file downloaded, decrypted, and verified: " + outputFilename);
            } else {
                System.out.println("Signature verification failed for secure file: " + receivedFilename);
            }
            Files.delete(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error occurred while processing secure file: " + receivedFilename);
        }
    }

    private static boolean verifySignature(byte[] fileContent, byte[] signatureBytes, PublicKey publicKey)
            throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(fileContent);
        return signature.verify(signatureBytes);
    }

    private static void receiveEncryptedFileAndDecrypt(DataInputStream dis, String patientUsername,
            String receivedFilename) throws IOException {
        try {
            KeyStore keystore = getKeyStore(patientUsername + ".keystore", patientUsername.toCharArray());

            long encryptedFileLength = dis.readLong();
            Path tempFile = Files.createTempFile("encrypted", ".tmp");
            try (OutputStream tempOut = Files.newOutputStream(tempFile)) {
                byte[] buffer = new byte[4096];
                long bytesRead = 0;
                while (bytesRead < encryptedFileLength) {
                    int bytesToRead = (int) Math.min(buffer.length, encryptedFileLength - bytesRead);
                    int bytesReceived = dis.read(buffer, 0, bytesToRead);
                    if (bytesReceived == -1) {
                        throw new EOFException("Unexpected end of stream while reading encrypted file");
                    }
                    tempOut.write(buffer, 0, bytesReceived);
                    bytesRead += bytesReceived;
                }
            }

            int encryptedKeyLength = dis.readInt();
            byte[] encryptedKeyContent = new byte[encryptedKeyLength];
            dis.readFully(encryptedKeyContent);

            // Decrypt the AES key
            PrivateKey privateKey = (PrivateKey) keystore.getKey(patientUsername + "alias",
                    patientUsername.toCharArray());
            System.out.println("Private key: " + privateKey);
            byte[] decryptedKeyBytes = decryptAESKey(encryptedKeyContent, privateKey);
            SecretKey decryptedKey = new SecretKeySpec(decryptedKeyBytes, "AES");

            // Decrypt the file
            byte[] encryptedFileBytes = Files.readAllBytes(tempFile);
            byte[] decryptedFileContent = decryptFile(encryptedFileBytes, decryptedKey);

            // Save the decrypted file
            String outputFilename = receivedFilename.replace(".cifrado", "");
            Path outputFilePath = Paths.get("Client", patientUsername, "Cifrados", outputFilename);
            Files.createDirectories(outputFilePath.getParent());
            Files.write(outputFilePath, decryptedFileContent, StandardOpenOption.CREATE, StandardOpenOption.WRITE);

            System.out.println("File downloaded and decrypted: " + outputFilename);
            Files.delete(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error occurred while decrypting the file: " + receivedFilename);
        }
    }

    private static byte[] decryptAESKey(byte[] encryptedKeyBytes, PrivateKey privateKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(encryptedKeyBytes);
    }

    private static byte[] decryptFile(byte[] encryptedFileBytes, SecretKey aesKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        return aesCipher.doFinal(encryptedFileBytes);
    }

    // Retrieves the AES key for a specific file from the keystore
    private static KeyStore getKeyStore(String keystorePath, char[] password) {
        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance("JKS");
            try (InputStream is = new FileInputStream(keystorePath)) {
                keystore.load(is, password);
            }
            // System.out.println("Keystore loaded successfully.");
        } catch (FileNotFoundException e) {
            System.err.println("Keystore file not found: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Failed to read keystore file: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm to check the integrity of the keystore cannot be found: " + e.getMessage());
        } catch (CertificateException e) {
            System.err.println("Any of the certificates in the keystore could not be loaded: " + e.getMessage());
        } catch (KeyStoreException e) {
            System.err.println("Keystore was not initialized: " + e.getMessage());
        }

        // if (keystore != null) {
        // try {
        // try {
        // printKeystoreAliases(keystore);
        // } catch (Exception e) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // }
        // } catch (Exception e) { // Catch any exception that occurs while printing the
        // aliases
        // System.err.println("Failed to print keystore aliases. Error: " +
        // e.getMessage());
        // e.printStackTrace();
        // }
        // }

        return keystore;
    }

    private static SecretKey getAESKeyFromKeystore(KeyStore keystore, String alias, char[] password) {
        try {
            System.out.println("Keystore type: " + keystore.getType());
            System.out.println(
                    "Trying to get key from keystore: " + alias + " with password: " + String.valueOf(password));
            Key key = keystore.getKey(alias, password);
            if (key != null) {
                System.out.println("Key algorithm: " + key.getAlgorithm());
                if (key instanceof SecretKey) {
                    return new SecretKeySpec(key.getEncoded(), "AES");
                } else {
                    System.err.println("Retrieved key is not a SecretKey: " + key.getClass().getName());
                }
            } else {
                System.err.println("No key found in the keystore for the alias: " + alias);
            }
        } catch (Exception e) {
            System.err.println("Failed to get key from keystore. Error: " + e.getMessage());
            e.printStackTrace();
            try {
                printKeystoreAliases(keystore);
            } catch (Exception ex) {
                System.err.println("Failed to print keystore aliases. Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
        return null;
    }

    // Retrieves the public key for verifying the signature from the keystore
    private static PublicKey getPublicKeyFromKeystore(KeyStore keystore, String alias) throws Exception {
        Certificate cert = keystore.getCertificate(alias);
        return cert.getPublicKey();
    }

    private static void printKeystoreAliases(KeyStore keystore) throws Exception {
        System.out.println("Keystore contains the following aliases:");
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias in keystore: " + alias);
        }
    }

}
