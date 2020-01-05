package license;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

public class LicenseRequest implements Serializable {
    private LicenseRequestParameters licenseRequestParameters;
    private byte[] userSignedLicenseRequestParameters;

    public LicenseRequest(LicenseRequestParameters licenseRequestParameters, PrivateKey userPrivateKey) {
        this.licenseRequestParameters = licenseRequestParameters;
        this.userSignedLicenseRequestParameters = signLicenseRequest(userPrivateKey);
    }

    // +===+ Helper Methods +==+
    private void printMessage(String message) {
        System.out.println(">[LICENSE REQUEST]\t" + message);
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

    private byte[] signLicenseRequest(PrivateKey privateKey) {
        byte[] signedLicenseRequestParameters = null;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(convertToByteArray(getLicenseRequestParameters()));
            signedLicenseRequestParameters = signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return signedLicenseRequestParameters;
    }
    // +======+

    // +===+ Getters and Setters +===+
    public LicenseRequestParameters getLicenseRequestParameters() {
        return licenseRequestParameters;
    }

    public void setLicenseRequestParameters(LicenseRequestParameters licenseRequestParameters) {
        this.licenseRequestParameters = licenseRequestParameters;
    }

    public byte[] getUserSignedLicenseRequestParameters() {
        return userSignedLicenseRequestParameters;
    }

    public void setUserSignedLicenseRequestParameters(byte[] userSignedLicenseRequestParameters) {
        this.userSignedLicenseRequestParameters = userSignedLicenseRequestParameters;
    }
    // +======+

    // +===+ Class methods +===+
    public boolean isValidUserSignature() {
        boolean validSignature = false;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(getLicenseRequestParameters().getCcCertificate());
            signature.update(convertToByteArray(getLicenseRequestParameters()));
            validSignature = signature.verify(getUserSignedLicenseRequestParameters());
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

    public boolean isValidCertificate() {
        X509Certificate x509Certificate = (X509Certificate) getLicenseRequestParameters().getCcCertificate();
        try {
            x509Certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            e.printStackTrace();
        }
        printMessage("Valid certificate");
        return true;
    }

    public boolean isValidApplication(ArrayList<byte[]> possibleApplications) {
        boolean validApplication = false;
        int index = 0;
        while (!validApplication && index < possibleApplications.size()) {
            if (Arrays.equals(getLicenseRequestParameters().getApplicationHash(), possibleApplications.get(index))) {
                validApplication = true;
            }
        }
        if (validApplication){
            printMessage("Valid Application");
        } else {
            printMessage("Invalid Application");
        }
        return validApplication;
    }

    public boolean isValidLicenseRequest(ArrayList<byte[]> possibleApplications) {
        boolean valid = isValidUserSignature() && isValidCertificate() && isValidApplication(possibleApplications);
        if (valid){
            printMessage("Valid license request");
        } else {
            printMessage("Invalid license request");
        }
        return valid;
    }

    public byte[] toByteArray() {
        return convertToByteArray(this);
    }
    // +======+
}
