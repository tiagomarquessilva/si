package license;

import license.LicenseParameters;

public class LicenseRequest {
    private LicenseParameters licenseParameters;
    private byte[] userPublicKey;
    private byte[] signedUserPublicKey;
    private byte[] signedUserCCCertificate;

    public LicenseRequest(LicenseParameters licenseParameters, byte[] userPublicKey, byte[] signedUserPublicKey, byte[] signedUserCCCertificate) {
        this.licenseParameters = licenseParameters;
        this.userPublicKey = userPublicKey;
        this.signedUserPublicKey = signedUserPublicKey;
        this.signedUserCCCertificate = signedUserCCCertificate;

    }

    public LicenseParameters getLicenseParameters() {
        return licenseParameters;
    }

    public void setLicenseParameters(LicenseParameters licenseParameters) {
        this.licenseParameters = licenseParameters;
    }

    public byte[] getUserPublicKey() {
        return userPublicKey;
    }

    public void setUserPublicKey(byte[] userPublicKey) {
        this.userPublicKey = userPublicKey;
    }

    public byte[] getSignedUserPublicKey() {
        return signedUserPublicKey;
    }

    public void setSignedUserPublicKey(byte[] signedUserPublicKey) {
        this.signedUserPublicKey = signedUserPublicKey;
    }

    public byte[] getSignedUserCCCertificate() {
        return signedUserCCCertificate;
    }

    public void setSignedUserCCCertificate(byte[] signedUserCCCertificate) {
        this.signedUserCCCertificate = signedUserCCCertificate;
    }
}
