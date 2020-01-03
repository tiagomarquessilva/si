import cryptography.HybridEncryption;
import cryptography.PasswordBasedEncryption;
import license.License;
import license.LicenseRequest;
import license.LicenseRequestParameters;
import oshi.SystemInfo;
import oshi.hardware.ComputerSystem;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.hardware.NetworkIF;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Time;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

public class Library {
    HybridEncryption encryptedLicense;
    PasswordBasedEncryption encryptedUserPrivateKey;
    PublicKey userPublicKey;
    String pathToApplication;
    PublicKey authorPublicKey;
    byte[] signedAuthorPublicKey;
    Provider citizenCardProvider;
    String pathToCommunicationDirectory;

    public Library(String pathToApplication, String pathToCommunicationDirectory) {
        this.pathToApplication = pathToApplication;
        this.pathToCommunicationDirectory = pathToCommunicationDirectory;
        this.citizenCardProvider = Security.getProvider("SunPKCS11-CartaoCidadao");
        this.authorPublicKey = getAuthorPublicKeyFromFile();
        signAuthorPublicKey();
        createKeyPair();
        writeToFile(new File("private_key.private_key"), getEncryptedUserPrivateKey().toByteArray());
    }

    // +===+ Helper Methods +===+
    private void printMessage(String message) {
        System.out.println(">[LIBRARY]" + message);
    }

    private void printCreatingMessage(String whatToCreate) {
        printMessage("Creating " + whatToCreate + "...");
    }

    private void printCreatedSuccessfullyMessage(String whatWhasCreated) {
        printMessage(whatWhasCreated + " created successfully");
    }

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

    private char[] getPassword() {
        Scanner input = new Scanner(System.in);
        System.out.print("Password: ");
        char[] password = input.nextLine().toCharArray();
        input.close();
        return password;
    }
    // +======+
    // +===+ Getters and Setters +===+

    public HybridEncryption getEncryptedLicense() {
        return encryptedLicense;
    }

    public void setEncryptedLicense(HybridEncryption encryptedLicense) {
        this.encryptedLicense = encryptedLicense;
    }

    public PasswordBasedEncryption getEncryptedUserPrivateKey() {
        return encryptedUserPrivateKey;
    }

    public void setEncryptedUserPrivateKey(PasswordBasedEncryption encryptedUserPrivateKey) {
        this.encryptedUserPrivateKey = encryptedUserPrivateKey;
    }

    public PublicKey getUserPublicKey() {
        return userPublicKey;
    }

    public void setUserPublicKey(PublicKey userPublicKey) {
        this.userPublicKey = userPublicKey;
    }

    public String getPathToApplication() {
        return pathToApplication;
    }

    public void setPathToApplication(String pathToApplication) {
        this.pathToApplication = pathToApplication;
    }

    public PublicKey getAuthorPublicKey() {
        return authorPublicKey;
    }

    public void setAuthorPublicKey(PublicKey authorPublicKey) {
        this.authorPublicKey = authorPublicKey;
    }

    public byte[] getSignedAuthorPublicKey() {
        return signedAuthorPublicKey;
    }

    public void setSignedAuthorPublicKey(byte[] signedAuthorPublicKey) {
        this.signedAuthorPublicKey = signedAuthorPublicKey;
    }

    public Provider getCitizenCardProvider() {
        return citizenCardProvider;
    }

    public void setCitizenCardProvider(Provider citizenCardProvider) {
        this.citizenCardProvider = citizenCardProvider;
    }

    public String getPathToCommunicationDirectory() {
        return pathToCommunicationDirectory;
    }

    public void setPathToCommunicationDirectory(String pathToCommunicationDirectory) {
        this.pathToCommunicationDirectory = pathToCommunicationDirectory;
    }

    // +======+
    // +===+ Class Methods +===+
    public PublicKey getAuthorPublicKeyFromFile(){
        PublicKey publicKey = null;
        try {
            publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(readFromFile(new File(getPathToCommunicationDirectory() + "/author.public_key"))));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return publicKey;
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
        setUserPublicKey(keyPair.getPublic());
        printCreatedSuccessfullyMessage("Key Pair");
        // protect private key
        printCreatingMessage("Encryption for the Private Key");
        encryptUserPrivateKey(keyPair.getPrivate());
        printCreatedSuccessfullyMessage("Encryption for the Private Key");

    }

    public void encryptUserPrivateKey(PrivateKey privateKey) {
        PasswordBasedEncryption encryptedPrivateKey = new PasswordBasedEncryption("AES", "CBC", "PKCS5Padding", 65536, 256);
        encryptedPrivateKey.encrypt(getPassword(), privateKey.getEncoded());
        setEncryptedUserPrivateKey(encryptedPrivateKey);
    }

    public PrivateKey getDecryptedPrivateKey() {
        PrivateKey privateKey = null;
        try {
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(getEncryptedUserPrivateKey().decrypt(getPassword())));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public License getDecryptedLicense() {
        License license = null;
        ByteArrayInputStream bis = new ByteArrayInputStream(getEncryptedLicense().decrypt(getDecryptedPrivateKey()));
        try {
            ObjectInputStream ois = new ObjectInputStream(bis);
            license = (License) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return license;
    }

    public byte[][] getMachineIdentifiers() {
        byte[][] machineIdentifiers = new byte[4][];
        SystemInfo systemInfo = new SystemInfo();
        HardwareAbstractionLayer systemHardwareInfo = systemInfo.getHardware();
        ComputerSystem computerSystem = systemHardwareInfo.getComputerSystem();

        // motherboard serial number
        machineIdentifiers[0] = hashInformation(computerSystem.getBaseboard().getSerialNumber().getBytes());

        // processor serial number
        machineIdentifiers[1] = hashInformation(systemHardwareInfo.getProcessor().getProcessorIdentifier().getProcessorID().getBytes());

        // mac addresses
        StringBuilder macAddressesConcat = new StringBuilder();
        for (NetworkIF networkInterface : systemHardwareInfo.getNetworkIFs()) {
            macAddressesConcat.append(networkInterface.getMacaddr());
        }
        machineIdentifiers[2] = hashInformation(macAddressesConcat.toString().getBytes());

        // make and model
        String makeAndModel = computerSystem.getManufacturer() + computerSystem.getModel();
        machineIdentifiers[3] = hashInformation(makeAndModel.getBytes());

        return machineIdentifiers;
    }

    public byte[] getApplicationHash() {
        return hashInformation(readFromFile(new File(getPathToApplication())));
    }

    public KeyStore getCitizenCardKeyPair() {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("PKCS11", getCitizenCardProvider());
            keyStore.load(null, null);
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    public Certificate getCitizenCardCertificate() {
        Certificate certificate = null;
        try {
            certificate = getCitizenCardKeyPair().getCertificate("CITIZEN AUTHENTICATION CERTIFICATE");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return certificate;
    }

    public boolean licenseExists() {
        return Files.exists(Paths.get("/license.license"));
    }

    public void signAuthorPublicKey(){
        try {
            Signature signature = Signature.getInstance("SHA1withRSA", getCitizenCardProvider());
            signature.initSign((PrivateKey) getCitizenCardKeyPair().getKey("CITIZEN AUTHENTICATION CERTIFICATE", null));
            signature.update(getAuthorPublicKey().getEncoded());
            setSignedAuthorPublicKey(signature.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    public boolean isValidAuthorPublicKey() {
        boolean validSignature = false;
        try {
            Signature signature = Signature.getInstance("SHA1withRSA", getCitizenCardProvider());
            System.out.println(getCitizenCardKeyPair().getCertificate("CITIZEN AUTHENTICATION CERTIFICATE").getPublicKey());
            signature.initVerify(getCitizenCardKeyPair().getCertificate("CITIZEN AUTHENTICATION CERTIFICATE").getPublicKey());
            signature.update(getAuthorPublicKey().getEncoded());
            validSignature = signature.verify(getSignedAuthorPublicKey());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | KeyStoreException e) {
            e.printStackTrace();
        }
        return validSignature;
    }

    public boolean startRegistration() {
        boolean successfulRegistration = false;
        if (isValidAuthorPublicKey()) {
            // get CC private key
            PrivateKey privateKey = null;
            try {
                privateKey = (PrivateKey) getCitizenCardKeyPair().getKey("CITIZEN AUTHENTICATION CERTIFICATE", null);
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                e.printStackTrace();
            }

            // create license request
            LicenseRequest licenseRequest = new LicenseRequest(new LicenseRequestParameters(getMachineIdentifiers(), getApplicationHash(), getUserPublicKey(), getCitizenCardCertificate()), privateKey);

            // encrypt license request
            HybridEncryption encryptedLicenseRequest = new HybridEncryption(getAuthorPublicKey());
            encryptedLicenseRequest.encrypt(licenseRequest.toByteArray());

            // send to author
            String filename = getPathToCommunicationDirectory() + "/" + licenseRequest.toString();
            writeToFile(new File(filename + ".license_request"), licenseRequest.toByteArray());

            // wait for author response
            while (Files.notExists(Paths.get(filename + ".license"))) {
                try {
                    TimeUnit.SECONDS.sleep(1);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // save encrypted license
            try {
                Files.move(Paths.get(filename + ".license"), Paths.get("/license.license"));
            } catch (IOException e) {
                e.printStackTrace();
            }

            ByteArrayInputStream bis = new ByteArrayInputStream(readFromFile(new File("/license.license")));
            try {
                ObjectInputStream ois = new ObjectInputStream(bis);
                setEncryptedLicense((HybridEncryption) ois.readObject());
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
            successfulRegistration = true;
        }
        return successfulRegistration;
    }

    public boolean isRegistered() {
        return getDecryptedLicense().isValidLicense(getAuthorPublicKey(), getMachineIdentifiers(), getApplicationHash());
    }

    public void showLicenseInfo() {
        License license = getDecryptedLicense();
        System.out.println(">[LICENSE]\tSignature:\t" + Base64.getEncoder().encodeToString(license.getAuthorSignedLicenseParameters()));
        System.out.println(">[LICENSE]\tExpiration Date:\t" + license.getLicenseParameters().getExpirationDate());
        System.out.println(">[LICENSE]\tMachine Identifiers:\t" +
                Base64.getEncoder().encodeToString(license.getLicenseParameters().getMachineIdentifiers()[0]) + " | " +
                Base64.getEncoder().encodeToString(license.getLicenseParameters().getMachineIdentifiers()[1]) + " | " +
                Base64.getEncoder().encodeToString(license.getLicenseParameters().getMachineIdentifiers()[2]) + " | " +
                Base64.getEncoder().encodeToString(license.getLicenseParameters().getMachineIdentifiers()[3]) + " | ");
        System.out.println(">[LICENSE]\tApplication:\t" + Base64.getEncoder().encodeToString(license.getLicenseParameters().getApplicationHash()));
        try {
            System.out.println(">[LICENSE]\tUser:\t" + Base64.getEncoder().encodeToString(license.getLicenseParameters().getCcCertificate().getEncoded()));
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
    }
    // +======+
}
