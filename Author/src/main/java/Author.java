import cryptography.HybridEncryption;
import cryptography.PasswordBasedEncryption;
import license.License;
import license.LicenseParameters;
import license.LicenseRequest;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

public class Author {

    private String pathToCommunicationDirectory;
    private String password;
    private byte[] encryptedPrivateKey;
    private byte[] publicKey;
    private int hoursUntilLicenseExpires;

    public Author(String pathToCommunicationDirectory, String password, int hoursUntilLicenseExpires) {
        this.pathToCommunicationDirectory = pathToCommunicationDirectory;
        this.password = password;
        this.hoursUntilLicenseExpires = hoursUntilLicenseExpires;
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

    private byte[] convertToByteArray(Object objectToConvert) {
        ByteArrayOutputStream bos = null;
        try {
            bos = new ByteArrayOutputStream();
            ObjectOutputStream os = new ObjectOutputStream(bos);
            os.writeObject(objectToConvert);
            os.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bos.toByteArray();
    }

    private byte[] readFromFile(File file) {
        byte[] content = null;
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

    private boolean fileOrDirectoryExists(String filePath) {
        return Files.exists(Paths.get(filePath));
    }
    // +======+

    // +===+ Getters and Setters +===+
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

    public byte[] getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    public void setEncryptedPrivateKey(byte[] encryptedPrivateKey) {
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public int getHoursUntilLicenseExpires() {
        return hoursUntilLicenseExpires;
    }

    public void setHoursUntilLicenseExpires(int hoursUntilLicenseExpires) {
        this.hoursUntilLicenseExpires = hoursUntilLicenseExpires;
    }

    // +======+

    // +===+ Class Methods +===+
    public void encryptPrivateKey(PrivateKey privateKey) {
        PasswordBasedEncryption encryptedPrivateKey = new PasswordBasedEncryption("AES", "CBC", "PKCS5Padding", 65536, 256);
        SecretKey secretKey = encryptedPrivateKey.createSecretKey(getPassword().toCharArray());
        encryptedPrivateKey.encrypt(secretKey, privateKey.getEncoded());
        setEncryptedPrivateKey(encryptedPrivateKey.getEncryptedInformation());
    }

    public void createDatabase() {
        // database name
        String databasePath = "database/database.db";
        try {
            // create database
            printCreatingMessage("Database");
            Connection databaseConnection = DriverManager.getConnection("jdbc:sqlite:" + databasePath);
            printCreatedSuccessfullyMessage("Database");
            // create tables
            printCreatingMessage("Tables");
            Statement query = databaseConnection.createStatement();
            // sql
            String sql = new String(readFromFile(new File("database/database_constructor.sql")));
            String[] splitedSQL = sql.split(";");
            for (String createTableSQL : splitedSQL) {
                query.addBatch(createTableSQL + ";");
            }
            query.executeBatch();
            query.close();
            databaseConnection.close();
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
        setPublicKey(keyPair.getPublic().getEncoded());
        printCreatedSuccessfullyMessage("Key Pair");
        // protect private key
        printCreatingMessage("Encryption for the Private Key");
        encryptPrivateKey(keyPair.getPrivate());
        printCreatedSuccessfullyMessage("Encryption for the Private Key");

    }

    public ArrayList<LicenseRequest> getLicenseRequestsInCommunicationDirectory() {
        // get directory
        File directory = new File(getPathToCommunicationDirectory());
        // get files with the extension .license_request
        File[] licenseRequestsFiles = directory.listFiles((dir, file) -> file.endsWith(".license_request"));
        ArrayList<LicenseRequest> licenseRequests = new ArrayList<LicenseRequest>();
        assert licenseRequestsFiles != null;
        // read each file and delete
        for (File file : licenseRequestsFiles) {
            ByteArrayInputStream bis = new ByteArrayInputStream(readFromFile(file));
            try {
                ObjectInputStream ois = new ObjectInputStream(bis);
                licenseRequests.add((LicenseRequest) ois.readObject());
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
            file.delete();
        }
        // return ArrayList of LicenseRequests
        return licenseRequests;
    }

    public void init() {
        // create key pair
        createKeyPair();
        // create database
        createDatabase();
    }

    public void start() {
        while (true) {
            // sleep for 1 sec
            try {
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            // get all license requests in directory
            System.out.println(">[AUTHOR] Checking if there is new license requests...");
            ArrayList<LicenseRequest> licenseRequests = getLicenseRequestsInCommunicationDirectory();

            // process each license requests
            for (LicenseRequest licenseRequest : licenseRequests) {
                // check if valid license request, create license if true
                if (licenseRequest.isValidLicenseRequest()) {
                    // create license
                    License license = new License(
                            new LicenseParameters(
                                    LocalDateTime.now().plusHours(getHoursUntilLicenseExpires()),
                                    licenseRequest.getLicenseRequestParameters().getMachineIdentifiers(),
                                    licenseRequest.getLicenseRequestParameters().getApplicationHash(),
                                    licenseRequest.getLicenseRequestParameters().getCcCertificate()
                            ),
                            getEncryptedPrivateKey(),
                            2
                    );

                    // add license parameters to database
                    INSERT INTO users(public_key, certificate) VALUES(3, 3);

                    INSERT INTO licenses(expiration_date, application_id, user_id) VALUES('29/01/2020', (SELECT id FROM applications WHERE hash = 1), (SELECT last_insert_rowid()));

                    INSERT INTO machine_identifiers(licenses_id, hash) VALUES((SELECT last_insert_rowid()), 1);
                    INSERT INTO machine_identifiers(licenses_id, hash) VALUES((SELECT licenses_id FROM machine_identifiers WHERE id = (SELECT last_insert_rowid())), 2);
                    INSERT INTO machine_identifiers(licenses_id, hash) VALUES((SELECT licenses_id FROM machine_identifiers WHERE id = (SELECT last_insert_rowid())), 3);
                    INSERT INTO machine_identifiers(licenses_id, hash) VALUES((SELECT licenses_id FROM machine_identifiers WHERE id = (SELECT last_insert_rowid())), 4);

                    // encrypt license
                    HybridEncryption encryptedLicense = new HybridEncryption(licenseRequest.getLicenseRequestParameters().getUserPublicKey());
                    encryptedLicense.encrypt(license.toByteArray());

                    // send encrypted license
                    writeToFile(
                            new File(getPathToCommunicationDirectory() + "/" + licenseRequest.toString() + ".license"),
                            convertToByteArray(encryptedLicense)
                    );
                }
            }
        }
    }
}
