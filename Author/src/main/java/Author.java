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
import java.security.cert.CertificateEncodingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class Author {

    private String pathToCommunicationDirectory;
    private String pathToDatabaseFile;
    private int hoursUntilLicenseExpires;
    private String password;
    private PasswordBasedEncryption encryptedPrivateKey;
    private PublicKey publicKey;

    public Author(String pathToCommunicationDirectory, String pathToDatabaseFile, int hoursUntilLicenseExpires, String password) {
        this.pathToCommunicationDirectory = pathToCommunicationDirectory;
        this.pathToDatabaseFile = pathToDatabaseFile;
        this.hoursUntilLicenseExpires = hoursUntilLicenseExpires;
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

    public String getPathToDatabaseFile() {
        return pathToDatabaseFile;
    }

    public void setPathToDatabaseFile(String pathToDatabaseFile) {
        this.pathToDatabaseFile = pathToDatabaseFile;
    }

    public int getHoursUntilLicenseExpires() {
        return hoursUntilLicenseExpires;
    }

    public void setHoursUntilLicenseExpires(int hoursUntilLicenseExpires) {
        this.hoursUntilLicenseExpires = hoursUntilLicenseExpires;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public PasswordBasedEncryption getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    public void setEncryptedPrivateKey(PasswordBasedEncryption encryptedPrivateKey) {
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
    // +======+

    // +===+ Class Methods +===+
    public void encryptPrivateKey(PrivateKey privateKey) {
        PasswordBasedEncryption encryptedPrivateKey = new PasswordBasedEncryption("AES", "CBC", "PKCS5Padding", 65536, 256);
        encryptedPrivateKey.encrypt(getPassword().toCharArray(), privateKey.getEncoded());
        setEncryptedPrivateKey(encryptedPrivateKey);
    }

    public PrivateKey decryptPrivateKey(char[] password) {
        PrivateKey privateKey = null;
        try {
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(getEncryptedPrivateKey().decrypt(getPassword().toCharArray())));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public void addLicenseToDatabase(License license, LicenseRequest licenseRequest) {
        try {
            Connection databaseConnection = DriverManager.getConnection("jdbc:sqlite:" + getPathToDatabaseFile());
            databaseConnection.setAutoCommit(false);
            PreparedStatement insertUser = databaseConnection.prepareStatement("INSERT INTO users(public_key, certificate) VALUES(?, ?);");
            insertUser.setBytes(1, licenseRequest.getLicenseRequestParameters().getUserPublicKey().getEncoded());
            insertUser.setBytes(2, licenseRequest.getLicenseRequestParameters().getCcCertificate().getEncoded());
            insertUser.executeUpdate();

            PreparedStatement insertLicense = databaseConnection.prepareStatement("INSERT INTO licenses(expiration_date, application_id, user_id) VALUES(?, (SELECT id FROM applications WHERE hash = ?), (SELECT last_insert_rowid()));");
            insertLicense.setDate(1, Date.valueOf(LocalDateTime.now().plusHours(getHoursUntilLicenseExpires()).toLocalDate()));
            insertLicense.setBytes(2, license.getLicenseParameters().getApplicationHash());
            insertLicense.executeUpdate();

            byte[][] machineIdentifiers = license.getLicenseParameters().getMachineIdentifiers();
            PreparedStatement insertMachineIdentifier1 = databaseConnection.prepareStatement("INSERT INTO machine_identifiers(licenses_id, hash) VALUES((SELECT last_insert_rowid()), ?);");
            insertMachineIdentifier1.setBytes(1, machineIdentifiers[0]);
            insertMachineIdentifier1.executeUpdate();

            PreparedStatement insertMachineIdentifier2 = databaseConnection.prepareStatement("INSERT INTO machine_identifiers(licenses_id, hash) VALUES((SELECT licenses_id FROM machine_identifiers WHERE id = (SELECT last_insert_rowid())), ?);");
            for (int index = 1; index < machineIdentifiers.length; index++) {
                insertMachineIdentifier1.setBytes(1, machineIdentifiers[index]);
                insertMachineIdentifier2.addBatch();
            }
            insertMachineIdentifier1.executeBatch();

            databaseConnection.commit();
            databaseConnection.close();
        } catch (SQLException | CertificateEncodingException e) {
            e.printStackTrace();
        }
    }

    public void processEncryptedLicenseRequest(HybridEncryption encryptedLicenseRequest) {
        // decrypt private key
        PrivateKey privateKey = decryptPrivateKey(getPassword().toCharArray());

        // decrypt license request
        LicenseRequest licenseRequest = null;
        ByteArrayInputStream bis = new ByteArrayInputStream(encryptedLicenseRequest.decrypt(privateKey));
        try {
            ObjectInputStream ois = new ObjectInputStream(bis);
            licenseRequest = (LicenseRequest) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        // check if valid license request, create license if true
        assert licenseRequest != null;
        if (licenseRequest.isValidLicenseRequest()) {

            // create license
            License license = new License(
                    new LicenseParameters(
                            LocalDateTime.now().plusHours(getHoursUntilLicenseExpires()),
                            licenseRequest.getLicenseRequestParameters().getMachineIdentifiers(),
                            licenseRequest.getLicenseRequestParameters().getApplicationHash(),
                            licenseRequest.getLicenseRequestParameters().getCcCertificate()
                    ),
                    privateKey,
                    2
            );

            // add license parameters to database
            addLicenseToDatabase(license, licenseRequest);

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

    public void createDatabase() {
        try {
            // create database
            printCreatingMessage("Database");
            Connection databaseConnection = DriverManager.getConnection("jdbc:sqlite:" + getPathToDatabaseFile());
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
        setPublicKey(keyPair.getPublic());
        printCreatedSuccessfullyMessage("Key Pair");
        // protect private key
        printCreatingMessage("Encryption for the Private Key");
        encryptPrivateKey(keyPair.getPrivate());
        printCreatedSuccessfullyMessage("Encryption for the Private Key");
        printCreatingMessage("File with Public Key");
        writeToFile(new File(getPathToCommunicationDirectory() + "/author.public_key"), keyPair.getPublic().getEncoded());
        printCreatedSuccessfullyMessage("File with Public Key");

    }

    public ArrayList<HybridEncryption> getLicenseRequestsInCommunicationDirectory() {
        // get directory
        File directory = new File(getPathToCommunicationDirectory());
        // get files with the extension .license_request
        File[] licenseRequestsFiles = directory.listFiles((dir, file) -> file.endsWith(".license_request"));
        ArrayList<HybridEncryption> encryptedLicenseRequests = new ArrayList<>();
        assert licenseRequestsFiles != null;
        // read each file and delete
        for (File file : licenseRequestsFiles) {
            ByteArrayInputStream bis = new ByteArrayInputStream(readFromFile(file));
            try {
                ObjectInputStream ois = new ObjectInputStream(bis);
                encryptedLicenseRequests.add((HybridEncryption) ois.readObject());
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
            file.delete();
        }
        // return ArrayList of LicenseRequests
        return encryptedLicenseRequests;
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
            ArrayList<HybridEncryption> encryptedLicenseRequests = getLicenseRequestsInCommunicationDirectory();

            // process each encrypted license requests
            for (HybridEncryption encryptedLicenseRequest : encryptedLicenseRequests) {
                processEncryptedLicenseRequest(encryptedLicenseRequest);
            }
        }
    }
}