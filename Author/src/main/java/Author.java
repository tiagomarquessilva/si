import cryptography.HybridEncryption;
import cryptography.PasswordBasedEncryption;
import license.License;
import license.LicenseParameters;
import license.LicenseRequest;
import org.zeroturnaround.zip.ZipUtil;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class Author {

    private String pathToCommunicationDirectory;
    private String pathToDatabaseFile;
    private String[] pathToApplications;
    private int hoursUntilLicenseExpires;
    private String password;
    private PasswordBasedEncryption encryptedPrivateKey;
    private PublicKey publicKey;

    public Author(String pathToCommunicationDirectory, String pathToDatabaseFile, String[] pathToApplications, int hoursUntilLicenseExpires, String password) {
        this.pathToCommunicationDirectory = pathToCommunicationDirectory;
        this.pathToDatabaseFile = pathToDatabaseFile;
        this.pathToApplications = pathToApplications;
        this.hoursUntilLicenseExpires = hoursUntilLicenseExpires;
        this.password = password;

        // create communication directory if not exists
        if (Files.notExists(Paths.get(pathToCommunicationDirectory))) {
            try {
                Files.createDirectory(Paths.get(pathToCommunicationDirectory));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        // init() if database not exists
        if (Files.notExists(Paths.get(getPathToDatabaseFile()))) {
            init();
        }
    }

    // +===+ Helper Methods +===+
    private void printMessage(String message) {
        System.out.println(">[AUTHOR]\t" + message);
    }

    private void printCreatingMessage(String whatToCreate) {
        printMessage("Creating " + whatToCreate + "...");
    }

    private void printCreatedSuccessfullyMessage(String whatWhasCreated) {
        printMessage(whatWhasCreated + " created successfully");
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
    // +======+

    // +===+ Getters and Setters +===+
    private String getPathToCommunicationDirectory() {
        return pathToCommunicationDirectory;
    }

    public String getPathToDatabaseFile() {
        return pathToDatabaseFile;
    }

    public String[] getPathToApplications() {
        return pathToApplications;
    }

    public int getHoursUntilLicenseExpires() {
        return hoursUntilLicenseExpires;
    }

    public String getPassword() {
        return password;
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
    private byte[] hashInformation(byte[] information) {
        MessageDigest hashFactory = null;
        try {
            hashFactory = MessageDigest.getInstance("SHA3-512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert hashFactory != null;
        hashFactory.update(information);
        return hashFactory.digest();
    }

    private void encryptPrivateKey(PrivateKey privateKey) {
        PasswordBasedEncryption encryptedPrivateKey = new PasswordBasedEncryption("AES", "CBC", "PKCS5Padding", 65536, 256);
        encryptedPrivateKey.encrypt(getPassword().toCharArray(), privateKey.getEncoded());
        setEncryptedPrivateKey(encryptedPrivateKey);
    }

    private PrivateKey decryptPrivateKey(char[] password) {
        PrivateKey privateKey = null;
        try {
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(getEncryptedPrivateKey().decrypt(getPassword().toCharArray())));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return privateKey;
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

        // add key pair to database
        printMessage("Adding key pair to database...");
        try {
            // connect to database
            Connection databaseConnection = DriverManager.getConnection("jdbc:sqlite:" + getPathToDatabaseFile());
            PreparedStatement insertKeyPair = databaseConnection.prepareStatement("INSERT INTO key_pair(encrypted_private_key, public_key) VALUES(?, ?);");
            insertKeyPair.setBytes(1, getEncryptedPrivateKey().toByteArray());
            insertKeyPair.setBytes(2, keyPair.getPublic().getEncoded());
            insertKeyPair.executeUpdate();
            insertKeyPair.close();
            databaseConnection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        printMessage("Added key pair to database...");

        // give public key to the public
        writeToFile(new File(getPathToCommunicationDirectory() + "/author.public_key"), keyPair.getPublic().getEncoded());

    }

    private ArrayList<HybridEncryption> getLicenseRequestsInCommunicationDirectory() {
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
            final boolean deleted = file.delete();
        }
        // return ArrayList of LicenseRequests
        return encryptedLicenseRequests;
    }

    private void addLicenseToDatabase(License license, LicenseRequest licenseRequest) {
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
                insertMachineIdentifier2.setBytes(1, machineIdentifiers[index]);
                insertMachineIdentifier2.addBatch();
            }
            insertMachineIdentifier2.executeBatch();

            databaseConnection.commit();
            databaseConnection.close();
        } catch (SQLException | CertificateEncodingException e) {
            e.printStackTrace();
        }
    }

    private void processEncryptedLicenseRequest(HybridEncryption encryptedLicenseRequest) {
        // decrypt private key
        printMessage("Decrypting Private Key..");
        PrivateKey privateKey = decryptPrivateKey(getPassword().toCharArray());

        // decrypt license request
        printMessage("Decrypting License Request..");
        LicenseRequest licenseRequest = null;
        ByteArrayInputStream bis = new ByteArrayInputStream(encryptedLicenseRequest.decrypt(privateKey));
        try {
            ObjectInputStream ois = new ObjectInputStream(bis);
            licenseRequest = (LicenseRequest) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        // get applications from database (most efficient to left in memory but want to get better at JDBC)
        ArrayList<byte[]> applicationsHash = new ArrayList<>();
        try {
            Connection databaseConnection = DriverManager.getConnection("jdbc:sqlite:" + getPathToDatabaseFile());
            Statement query = databaseConnection.createStatement();
            ResultSet results = query.executeQuery("SELECT hash FROM applications;");
            while (results.next()){
                applicationsHash.add(results.getBytes("hash"));
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }

        // check if valid license request, create license if true
        assert licenseRequest != null;
        if (licenseRequest.isValidLicenseRequest(applicationsHash)) {
            printMessage("Valid License Request!");
            // create license
            printCreatingMessage("License");
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
            printCreatedSuccessfullyMessage("License");

            // add license parameters to database
            printMessage("Adding License to Database...");
            addLicenseToDatabase(license, licenseRequest);
            printMessage("Added License to Database successfully");

            // encrypt license
            printCreatingMessage("Encryption for the License");
            HybridEncryption encryptedLicense = new HybridEncryption(licenseRequest.getLicenseRequestParameters().getUserPublicKey());
            encryptedLicense.encrypt(license.toByteArray());
            printCreatedSuccessfullyMessage("Encryption for the License");

            // send encrypted license
            printMessage("Sending Encrypted License to User...");
            writeToFile(
                    new File(getPathToCommunicationDirectory() + "/" + Arrays.hashCode(licenseRequest.getUserSignedLicenseRequestParameters()) + ".license"),
                    convertToByteArray(encryptedLicense)
            );
            printMessage("Sent Encrypted License to User");

        } else {
            printMessage("Invalid License Request!");
        }

    }

    // create new database and keypair
    public void init() {

        // create database
        if (Files.exists(Paths.get(getPathToDatabaseFile()))) {
            try {
                Files.delete(Paths.get(getPathToDatabaseFile()));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        createDatabase();

        // create key pair
        createKeyPair();

        // add application to database
        try {
            // connect to database
            printMessage("Adding applications to database...");
            Connection databaseConnection = DriverManager.getConnection("jdbc:sqlite:" + getPathToDatabaseFile());
            PreparedStatement insertAppHash = databaseConnection.prepareStatement("INSERT INTO applications(hash) VALUES(?);");
            for (String application : getPathToApplications()) {
                File file = new File(application);
                if (file.isDirectory()){
                    ByteArrayOutputStream app = new ByteArrayOutputStream();
                    ZipUtil.pack(file, app);
                    insertAppHash.setBytes(1, hashInformation(app.toByteArray()));
                } else {
                    insertAppHash.setBytes(1, hashInformation(readFromFile(file)));
                }
                insertAppHash.addBatch();
            }
            insertAppHash.executeBatch();
            insertAppHash.close();
            databaseConnection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        printMessage("Added applications to database");
    }

    // load keypair and check for new license requests
    public void start() {
        if (Files.exists(Paths.get(getPathToDatabaseFile()))) {
            printMessage("Loading key pair to memory...");
            try {
                Connection databaseConnection = DriverManager.getConnection("jdbc:sqlite:" + getPathToDatabaseFile());
                Statement getKeyPair = databaseConnection.createStatement();
                ResultSet keyPair = getKeyPair.executeQuery("SELECT encrypted_private_key, public_key FROM key_pair;");

                ByteArrayInputStream bis1 = new ByteArrayInputStream(keyPair.getBytes("encrypted_private_key"));
                try {
                    ObjectInputStream ois1 = new ObjectInputStream(bis1);
                    setEncryptedPrivateKey((PasswordBasedEncryption) ois1.readObject());
                } catch (IOException | ClassNotFoundException e) {
                    e.printStackTrace();
                }

                try {
                    setPublicKey(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyPair.getBytes("public_key"))));
                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                getKeyPair.close();
                databaseConnection.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
            printMessage("Loaded key pair to memory...");
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
        } else {
            printMessage("Database does not exist. Please call init() after creating Author");
        }
    }
}