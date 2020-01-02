import cryptography.HybridEncryption;
import cryptography.PasswordBasedEncryption;
import license.LicenseRequest;
import license.LicenseRequestParameters;
import oshi.SystemInfo;
import oshi.hardware.ComputerSystem;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.hardware.NetworkIF;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Time;
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

    // +===+ Helper Methods +===+
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
    public PrivateKey getDecryptedPrivateKey() {
        PrivateKey privateKey = null;
        try {
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(getEncryptedUserPrivateKey().decrypt(getPassword())));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return privateKey;
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
            keyStore.load(null);
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

    public boolean isValidAuthorPublicKey() {
        boolean validSignature = false;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA", getCitizenCardProvider());
            signature.initVerify(getAuthorPublicKey());
            signature.update(getAuthorPublicKey().getEncoded());
            validSignature = signature.verify(getSignedAuthorPublicKey());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return validSignature;
    }

    public boolean startRegistration() {
        boolean successfulRegistration = false;
        if (isValidAuthorPublicKey()) {
            // create license request
            LicenseRequest licenseRequest = new LicenseRequest(new LicenseRequestParameters(getMachineIdentifiers(), getApplicationHash(), getUserPublicKey(), getCitizenCardCertificate()), getDecryptedPrivateKey());

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
            successfulRegistration = true;
        }
        return successfulRegistration;
    }

    public boolean isRegistered() {
        return true;
    }

    public void showLicenseInfo() {

    }
    // +======+
}
