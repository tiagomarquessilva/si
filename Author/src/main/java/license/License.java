package license;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class License implements Serializable {

    private byte[] authorSignedLicenseParameters;
    private int numberOfMachineIdentifiersThatCanChange;
    private LicenseParameters licenseParameters;

    public License(LicenseParameters licenseParameters, PrivateKey privateKey, int numberOfMachineIdentifiersThatCanChange) {
        this.licenseParameters = licenseParameters;
        this.numberOfMachineIdentifiersThatCanChange = numberOfMachineIdentifiersThatCanChange;
        this.authorSignedLicenseParameters = signLicense(privateKey);
    }

    // +===+ Helper Methods +==+
    private void printMessage(String message) {
        System.out.println(">[LICENSE]\t" + message);
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

    private byte[] signLicense(PrivateKey privateKey) {
        printMessage("Signing License...");
        byte[] signedLicenseParameters = null;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(convertToByteArray(getLicenseParameters()));
            signedLicenseParameters = signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return signedLicenseParameters;
    }
    // +======+

    // +===+ Getters and Setters +===+
    public byte[] getAuthorSignedLicenseParameters() {
        return authorSignedLicenseParameters;
    }

    public void setAuthorSignedLicenseParameters(byte[] authorSignedLicenseParameters) {
        this.authorSignedLicenseParameters = authorSignedLicenseParameters;
    }

    public int getNumberOfMachineIdentifiersThatCanChange() {
        return numberOfMachineIdentifiersThatCanChange;
    }

    public void setNumberOfMachineIdentifiersThatCanChange(int numberOfMachineIdentifiersThatCanChange) {
        this.numberOfMachineIdentifiersThatCanChange = numberOfMachineIdentifiersThatCanChange;
    }

    public LicenseParameters getLicenseParameters() {
        return licenseParameters;
    }

    public void setLicenseParameters(LicenseParameters licenseParameters) {
        this.licenseParameters = licenseParameters;
    }
    // +======+

    // +===+ Class Methods +===+
    public boolean isValidAuthorSignature(PublicKey publicKey) {
        boolean validSignature = false;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(convertToByteArray(getLicenseParameters()));
            validSignature = signature.verify(getAuthorSignedLicenseParameters());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        if (validSignature) {
            printMessage("Valid signature");
        } else {
            printMessage("Invalid signature");
        }
        return validSignature;
    }

    public boolean isExpired() {
        boolean expired = LocalDateTime.now().isBefore(getLicenseParameters().getExpirationDate());
        if (expired) {
            printMessage("Not expired");
        } else {
            printMessage("Expired");
        }
        return expired;
    }

    public boolean isValidMachine(byte[][] currentMachineIdentifiers) {
        int numberOfIdentifiersFound = 0;
        for (byte[] machineIdentifier1 : currentMachineIdentifiers) {
            byte[][] machineIdentifiers = getLicenseParameters().getMachineIdentifiers();
            for (byte[] machineIdentifier2 : machineIdentifiers) {
                if (Arrays.equals(machineIdentifier1, machineIdentifier2)){
                    numberOfIdentifiersFound++;
                }
            }
        }

        boolean valid = numberOfIdentifiersFound >= getNumberOfMachineIdentifiersThatCanChange();
        if (valid) {
            printMessage("Identical machine identifiers: " + numberOfIdentifiersFound + "/4. Maximum of different identifiers: " + getNumberOfMachineIdentifiersThatCanChange() + ". Valid");
        } else {
            printMessage("Identical machine identifiers: " + numberOfIdentifiersFound + "/4. Maximum of different identifiers: " + getNumberOfMachineIdentifiersThatCanChange() + ". Invalid");
        }
        return valid;
    }

    public boolean isValidApplication(byte[] currentApplicationHash) {
        boolean valid = Arrays.equals(getLicenseParameters().getApplicationHash(), currentApplicationHash);
        if (valid) {
            printMessage("Valid application");
        } else {
            printMessage("Invalid application");
        }
        return valid;
    }

    public boolean isValidUser(PrivateKey privateKey) {
        boolean validSignature = false;

        Random randomInts = new SecureRandom();
        byte[] randomBytes = new byte[16];
        randomInts.nextBytes(randomBytes);

        X509Certificate x509Certificate = (X509Certificate) getLicenseParameters().getCcCertificate();
        try {
            x509Certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            e.printStackTrace();
        }
        printMessage("Valid certificate");

        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(randomBytes);
            byte[] signedBytes = signature.sign();

            signature.initVerify(getLicenseParameters().getCcCertificate());
            signature.update(randomBytes);
            validSignature = signature.verify(signedBytes);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        if (validSignature){
            printMessage("Valid user");
        } else {
            printMessage("Invalid user");
        }
        return validSignature;
    }

    public boolean isValidLicense(PublicKey authorPublicKey, byte[][] currentMachineIdentifiers, byte[] currentApplicationHash, PrivateKey currentUser) {
        boolean valid = isValidAuthorSignature(authorPublicKey) && isExpired() && isValidMachine(currentMachineIdentifiers) && isValidApplication(currentApplicationHash) && isValidUser(currentUser);
        if (valid){
            printMessage("Valid license");
        } else {
            printMessage("Invalid license");
        }
        return valid;
    }

    public byte[] toByteArray() {
        return convertToByteArray(this);
    }
    // +======+
}
