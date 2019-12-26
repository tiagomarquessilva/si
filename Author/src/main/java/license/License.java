package license;

import license.LicenseParameters;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Arrays;

public class License implements Serializable {

    private byte[] authorSignature;
    private int numberOfMachineIdentifiersThatCanChange;
    private LicenseParameters licenseParameters;

    public License(LicenseParameters licenseParameters, PrivateKey privateKey, int numberOfMachineIdentifiersThatCanChange) {
        this.licenseParameters = licenseParameters;
        this.numberOfMachineIdentifiersThatCanChange = numberOfMachineIdentifiersThatCanChange;
        this.authorSignature = signLicense(privateKey);
    }

    // +===+ Helper Methods +==+
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

    private byte[] signLicense(PrivateKey privateKey){
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
    public byte[] getAuthorSignature() {
        return authorSignature;
    }

    public void setAuthorSignature(byte[] authorSignature) {
        this.authorSignature = authorSignature;
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

    public boolean isValidAuthorSignature(byte[] publicKeyBytes) {
        boolean validSignature = false;
        try {
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(convertToByteArray(getLicenseParameters()));
            validSignature = signature.verify(getAuthorSignature());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return validSignature;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isBefore(getLicenseParameters().getExpirationDate());
    }

    public boolean isValidMachine(byte[][] currentMachineIdentifiers) {
        int numberOfIdentifiersNotFound = 0;
        for (byte[] machineIdentifier : currentMachineIdentifiers) {
            if (!Arrays.asList(getLicenseParameters().getMachineIdentifiers()).contains(machineIdentifier)) {
                numberOfIdentifiersNotFound++;
            }
        }

        return numberOfIdentifiersNotFound >= getNumberOfMachineIdentifiersThatCanChange();
    }

    public boolean isValidApplication(byte[] currentApplicationHash){
        return Arrays.equals(getLicenseParameters().getApplicationHash(), currentApplicationHash);
    }

    public boolean isValidLicense(byte[] userPublicKeyBytes, byte[][] currentMachineIdentifiers, byte[] currentApplicationHash){
        return isValidAuthorSignature(userPublicKeyBytes) && isExpired() && isValidMachine(currentMachineIdentifiers) && isValidApplication(currentApplicationHash);
    }

    public byte[] toByteArray() {
        return convertToByteArray(this);
    }
}
