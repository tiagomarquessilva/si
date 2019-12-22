import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class Author {

    private String pathToCommunicationDirectory;
    private String password;
    private byte[] encryptedPrivateKey;

    public Author(String pathToCommunicationDirectory, String password) {
        this.pathToCommunicationDirectory = pathToCommunicationDirectory;
        this.password = password;
    }

    // +===+ Helper Methods +===+

    private void printMessage(String message) {
        System.out.println(">[AUTHOR]" + message);
    }

    private void printCreatingMessage(String whatToCreate) {
        printMessage("Creating " + whatToCreate + "...");
    }

    private void printCreatedSuccessfullyMessage(String whatWhasCreated) {
        printMessage(whatWhasCreated + " created successfully");
    }

    private byte[] readFromFile(File file) {
        byte[] content = new byte[Math.toIntExact(file.length())];
        try {
            content = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return content;
    }

    private void writeToFile(File file, byte[] content) {
        try {
            Files.write(Paths.get(file.getAbsolutePath()), content);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private boolean fileOrDirectoryExists(String filePath){
        return Files.exists(filePath);
    }
    // +======+

    public String getPathToCommunicationDirectory() {
        return pathToCommunicationDirectory;
    }

    public void setPathToCommunicationDirectory(String pathToCommunicationDirectory) {
        this.pathToCommunicationDirectory = pathToCommunicationDirectory;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void encryptPrivateKey(PrivateKey privateKey){
        
    }

    public void createDatabase() {
        // database name
        String databaseName = "database";
        // sql to create table
        //String sql = "DROP TABLE licenses; CREATE TABLE IF NOT EXISTS licenses (cc_certificate BLOB NOT NULL);";
        String sql = "CREATE TABLE IF NOT EXISTS licenses (cc_certificate BLOB NOT NULL, expiration_date TIMESTAMP, NOT NULL);";
        try {
            // create database
            printCreatingMessage("Database");
            Connection databaseConnection = DriverManager.getConnection("jdbc:sqlite:" + databaseName + ".db");
            printCreatedSuccessfullyMessage("Database");
            // create tables
            printCreatingMessage("Tables");
            Statement query = databaseConnection.createStatement();
            query.execute(sql);
            printCreatedSuccessfullyMessage("Tables");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void createKeyPair() {
        // create key pair
        printCreatingMessage("Key Pair");
        KeyPairGenerator keyGenerator = null;
        try {
            keyGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert keyGenerator != null;
        keyGenerator.initialize(2048);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        printCreatedSuccessfullyMessage("Key Pair");
        // protect private key
        printCreatingMessage("Protection for the Private Key");
        if(fileOrDirectoryExists()){
            encryptPrivateKey();
        }
        printCreatedSuccessfullyMessage("Protection for the Private Key");

    }

    public ArrayList<byte[]> getLicenseRequestsInCommunicationDirectory() {
        File directory = new File(getPathToCommunicationDirectory());
        File[] licenseRequests = directory.listFiles((dir, file) -> file.endsWith(".license_request"));
        ArrayList<byte[]> licenseRequestsBytes = new ArrayList<byte[]>();
        assert licenseRequests != null;
        for (File file : licenseRequests) {
            licenseRequestsBytes.add(readFromFile(file));
            file.delete();
        }
        return licenseRequestsBytes;
    }

    public void init() {
        // create key pair
        createKeyPair();
        // create database
        createDatabase();
    }

    public void start() throws InterruptedException, IOException {
        while (true) {
            // sleep for 1 sec
            TimeUnit.SECONDS.sleep(1);
            System.out.println(">[AUTHOR] Checking if there is new license requests...");
            //check if file format is in the folder
            ArrayList<byte[]> licenseRequest = getLicenseRequestsInCommunicationDirectory();
        }
    }
}
