import cryptography.HybridEncryption;
import cryptography.PasswordBasedEncryption;
import license.License;
import license.LicenseRequest;
import license.LicenseRequestParameters;
import org.zeroturnaround.zip.ZipUtil;
import oshi.SystemInfo;
import oshi.hardware.ComputerSystem;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.hardware.NetworkIF;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class Library {
    String pathToApplication;
    String pathToCommunicationDirectory;
    PasswordBasedEncryption encryptedLibraryPrivateKey;
    PublicKey libraryPublicKey;
    PublicKey authorPublicKey;
    byte[] signedAuthorPublicKey;
    Provider citizenCardProvider;
    HybridEncryption encryptedLicense;

    public Library(String pathToApplication, String pathToCommunicationDirectory, String operatingSystem) {
        // create communication directory if not exists
        if (Files.notExists(Paths.get(pathToCommunicationDirectory))) {
            try {
                Files.createDirectory(Paths.get(pathToCommunicationDirectory));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        this.pathToApplication = pathToApplication;
        this.pathToCommunicationDirectory = pathToCommunicationDirectory;

        // add CC provider to Java
        Provider provider = Security.getProvider("SunPKCS11");
        if (operatingSystem.equals("windows")) {
            provider = provider.configure("pkcs11ccwin.cfg");
        } else if (operatingSystem.equals("linux")) {
            provider = provider.configure("pkcs11cclinux.cfg");
        }
        Security.addProvider(provider);

        this.citizenCardProvider = Security.getProvider("SunPKCS11-CartaoCidadao");
        if (Files.exists(Paths.get("library.license"))) {
            this.encryptedLicense = getEncryptedLicenseFromFile();
        } else {
            this.encryptedLicense = null;
        }
        if (Files.exists(Paths.get("library.private_key")) && Files.exists(Paths.get("library.public_key"))) {
            this.libraryPublicKey = getLibraryPublicKeyFromFile();
            this.encryptedLibraryPrivateKey = getEncryptedLibraryPrivateKeyFromFile();
        } else {
            createKeyPair();
            writeToFile(new File("library.private_key"), getEncryptedLibraryPrivateKey().toByteArray());
            writeToFile(new File("library.public_key"), getLibraryPublicKey().getEncoded());
        }
        if (Files.exists(Paths.get(getPathToCommunicationDirectory() + "/author.public_key"))){
            this.authorPublicKey = getAuthorPublicKeyFromFile();
            signAuthorPublicKey();
        } else {
            this.authorPublicKey = null;
            this.signedAuthorPublicKey = null;
        }

    }

    // +===+ Helper Methods +===+
    private void printMessage(String message) {
        System.out.println(">[LIBRARY]\t" + message);
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

    // +======+
    // +===+ Getters and Setters +===+

    private HybridEncryption getEncryptedLicense() {
        return encryptedLicense;
    }

    private void setEncryptedLicense(HybridEncryption encryptedLicense) {
        this.encryptedLicense = encryptedLicense;
    }

    private PasswordBasedEncryption getEncryptedLibraryPrivateKey() {
        return encryptedLibraryPrivateKey;
    }

    private void setEncryptedLibraryPrivateKey(PasswordBasedEncryption encryptedLibraryPrivateKey) {
        this.encryptedLibraryPrivateKey = encryptedLibraryPrivateKey;
    }

    private PublicKey getLibraryPublicKey() {
        return libraryPublicKey;
    }

    private void setLibraryPublicKey(PublicKey libraryPublicKey) {
        this.libraryPublicKey = libraryPublicKey;
    }

    private String getPathToApplication() {
        return pathToApplication;
    }

    private void setPathToApplication(String pathToApplication) {
        this.pathToApplication = pathToApplication;
    }

    private PublicKey getAuthorPublicKey() {
        return authorPublicKey;
    }

    private void setAuthorPublicKey(PublicKey authorPublicKey) {
        this.authorPublicKey = authorPublicKey;
    }

    private byte[] getSignedAuthorPublicKey() {
        return signedAuthorPublicKey;
    }

    private void setSignedAuthorPublicKey(byte[] signedAuthorPublicKey) {
        this.signedAuthorPublicKey = signedAuthorPublicKey;
    }

    private Provider getCitizenCardProvider() {
        return citizenCardProvider;
    }

    private void setCitizenCardProvider(Provider citizenCardProvider) {
        this.citizenCardProvider = citizenCardProvider;
    }

    private String getPathToCommunicationDirectory() {
        return pathToCommunicationDirectory;
    }

    private void setPathToCommunicationDirectory(String pathToCommunicationDirectory) {
        this.pathToCommunicationDirectory = pathToCommunicationDirectory;
    }

    // +======+
    // +===+ Class Methods +===+
    private void createKeyPair() {
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
        setLibraryPublicKey(keyPair.getPublic());
        printCreatedSuccessfullyMessage("Key Pair");
        // protect private key
        printCreatingMessage("Encryption for the Private Key");
        encryptLibraryPrivateKey(keyPair.getPrivate());
        printCreatedSuccessfullyMessage("Encryption for the Private Key");

    }

    private void signAuthorPublicKey() {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(getCitizenCardPrivateKey());
            signature.update(getAuthorPublicKey().getEncoded());
            setSignedAuthorPublicKey(signature.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }

    private byte[][] getMachineIdentifiers() {
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

    private byte[] getApplicationHash() {
        byte[] hash = null;
        File file = new File(getPathToApplication());
        if (file.isDirectory()){
            ByteArrayOutputStream app = new ByteArrayOutputStream();
            ZipUtil.pack(file, app);
            hash = hashInformation(app.toByteArray());
        } else {
            hash = hashInformation(readFromFile(file));
        }
        return hash;
    }

    private char[] getPassword() {
        /*
        Scanner input = new Scanner(System.in);
        System.out.print("Password: ");
        char[] password = input.next().toCharArray();
        input.close();
        return password;
        */
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        char[] password = null;
        System.out.print("Password: ");
        try {
            password = br.readLine().toCharArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return password;
    }

    private PublicKey getAuthorPublicKeyFromFile() {
        PublicKey publicKey = null;
        try {
            publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(readFromFile(new File(getPathToCommunicationDirectory() + "/author.public_key"))));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    private PublicKey getLibraryPublicKeyFromFile() {
        PublicKey publicKey = null;
        try {
            publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(readFromFile(new File("library.public_key"))));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    private PasswordBasedEncryption getEncryptedLibraryPrivateKeyFromFile() {
        PasswordBasedEncryption encryptedPrivateKey = null;
        ByteArrayInputStream bis = new ByteArrayInputStream(readFromFile(new File("library.private_key")));
        try {
            ObjectInputStream ois = new ObjectInputStream(bis);
            encryptedPrivateKey = (PasswordBasedEncryption) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return encryptedPrivateKey;
    }

    private HybridEncryption getEncryptedLicenseFromFile() {
        HybridEncryption encryptedLicense = null;
        ByteArrayInputStream bis = new ByteArrayInputStream(readFromFile(new File("library.license")));
        try {
            ObjectInputStream ois = new ObjectInputStream(bis);
            encryptedLicense = (HybridEncryption) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return encryptedLicense;
    }

    private PrivateKey getDecryptedLibraryPrivateKey() {
        PrivateKey privateKey = null;
        try {
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(getEncryptedLibraryPrivateKey().decrypt(getPassword())));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    private License getDecryptedLicense() {
        License license = null;
        ByteArrayInputStream bis = new ByteArrayInputStream(getEncryptedLicense().decrypt(getDecryptedLibraryPrivateKey()));
        try {
            ObjectInputStream ois = new ObjectInputStream(bis);
            license = (License) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return license;
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

    private void encryptLibraryPrivateKey(PrivateKey privateKey) {
        PasswordBasedEncryption encryptedPrivateKey = new PasswordBasedEncryption("AES", "CBC", "PKCS5Padding", 65536, 256);
        encryptedPrivateKey.encrypt(getPassword(), privateKey.getEncoded());
        setEncryptedLibraryPrivateKey(encryptedPrivateKey);
    }

    private KeyStore getCitizenCardKeyPair() {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("PKCS11", getCitizenCardProvider());
            keyStore.load(null, null);
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    private Certificate getCitizenCardCertificate() {
        Certificate certificate = null;
        try {
            certificate = getCitizenCardKeyPair().getCertificate("CITIZEN AUTHENTICATION CERTIFICATE");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return certificate;
    }

    private PrivateKey getCitizenCardPrivateKey() {
        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey) getCitizenCardKeyPair().getKey("CITIZEN AUTHENTICATION CERTIFICATE", null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    private boolean isValidAuthorPublicKey() {
        boolean validSignature = true;

        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(getCitizenCardCertificate());
            signature.update(getAuthorPublicKey().getEncoded());
            validSignature = signature.verify(getSignedAuthorPublicKey());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        return validSignature;
    }

    private void register() {
        if (isValidAuthorPublicKey()) {
            // create license request and sign
            LicenseRequest licenseRequest = new LicenseRequest(new LicenseRequestParameters(getMachineIdentifiers(), getApplicationHash(), getLibraryPublicKey(), getCitizenCardCertificate()), getCitizenCardPrivateKey());

            // print license request
            System.out.println(">[LICENSE REQUEST]\tSignature:\t" + Base64.getEncoder().encodeToString(licenseRequest.getUserSignedLicenseRequestParameters()));
            System.out.println(">[LICENSE REQUEST]\tMachine Identifiers:\t" +
                    Base64.getEncoder().encodeToString(licenseRequest.getLicenseRequestParameters().getMachineIdentifiers()[0]) + " | " +
                    Base64.getEncoder().encodeToString(licenseRequest.getLicenseRequestParameters().getMachineIdentifiers()[1]) + " | " +
                    Base64.getEncoder().encodeToString(licenseRequest.getLicenseRequestParameters().getMachineIdentifiers()[2]) + " | " +
                    Base64.getEncoder().encodeToString(licenseRequest.getLicenseRequestParameters().getMachineIdentifiers()[3]) + " | ");
            System.out.println(">[LICENSE REQUEST]\tApplication:\t" + Base64.getEncoder().encodeToString(licenseRequest.getLicenseRequestParameters().getApplicationHash()));
            System.out.println(">[LICENSE REQUEST]\tLibrary Public Key:\t" + Base64.getEncoder().encodeToString(licenseRequest.getLicenseRequestParameters().getUserPublicKey().getEncoded()));
            try {
                System.out.println(">[LICENSE REQUEST]\tCitizen Card Certificate:\t" + Base64.getEncoder().encodeToString(licenseRequest.getLicenseRequestParameters().getCcCertificate().getEncoded()));
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            }

            // encrypt license request
            HybridEncryption encryptedLicenseRequest = new HybridEncryption(getAuthorPublicKey());
            encryptedLicenseRequest.encrypt(licenseRequest.toByteArray());

            // send to author
            String filename = getPathToCommunicationDirectory() + "/" + Arrays.hashCode(licenseRequest.getUserSignedLicenseRequestParameters());
            writeToFile(new File(filename + ".license_request"), encryptedLicenseRequest.toByteArray());

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
                Files.deleteIfExists(Paths.get("library.license"));
                Files.move(Paths.get(filename + ".license"), Paths.get("library.license"));
            } catch (IOException e) {
                e.printStackTrace();
            }

            ByteArrayInputStream bis = new ByteArrayInputStream(readFromFile(new File("library.license")));
            try {
                ObjectInputStream ois = new ObjectInputStream(bis);
                setEncryptedLicense((HybridEncryption) ois.readObject());
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    public boolean startRegistration() {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        boolean start = false;
        printMessage("Application not registered. Do you which do register? (y/n)");
        try {
            switch (br.readLine()) {
                case "y":
                    printMessage("Registering Application...");
                    Files.deleteIfExists(Paths.get("library.license"));
                    register();
                    start = true;
                    break;
                case "n":
                    break;
                default:
                    printMessage("Invalid Answer! Please answer again.");
                    start = startRegistration();
                    break;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return start;
    }

    public boolean isRegistered() {
        boolean registered = false;
        if (Files.exists(Paths.get("library.license"))){
            registered = getDecryptedLicense().isValidLicense(getAuthorPublicKey(), getMachineIdentifiers(), getApplicationHash(), getCitizenCardPrivateKey());
        }
        return  registered;

    }

    public void showLicenseInfo() {
        if (Files.exists(Paths.get("library.license"))) {
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

        } else {
            printMessage("License does not exist!");
        }
    }
    // +======+
}
