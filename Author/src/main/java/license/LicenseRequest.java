package license;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class LicenseRequest implements Serializable{
    private LicenseRequestParameters licenseRequestParameters;
    private byte[] userSignedLicenseRequestParameters;

    public LicenseRequest(LicenseRequestParameters licenseRequestParameters, PrivateKey userPrivateKey) {
        this.licenseRequestParameters = licenseRequestParameters;
        this.userSignedLicenseRequestParameters = signLicenseRequest(userPrivateKey);
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

    private byte[] signLicenseRequest(PrivateKey privateKey){
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
            signature.initVerify(getLicenseRequestParameters().getUserPublicKey());
            signature.update(convertToByteArray(getLicenseRequestParameters()));
            validSignature = signature.verify(getUserSignedLicenseRequestParameters());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return validSignature;
    }

    public boolean isValidLicenseRequest(){
        // TODO: Validar certificado aka escrever este método
        return true;
    }

    public byte[] toByteArray(){
        return convertToByteArray(this);
    }
    // +======+
}
