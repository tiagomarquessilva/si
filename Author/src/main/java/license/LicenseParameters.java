package license;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.time.LocalDateTime;

public class LicenseParameters implements Serializable {
    private LocalDateTime expirationDate;
    private byte[][] machineIdentifiers;
    private byte[] applicationHash;
    private Certificate ccCertificate;

    public LicenseParameters(LocalDateTime expirationDate, byte[][] machineIdentifiers, byte[] applicationHash, Certificate ccCertificate) {
        this.expirationDate = expirationDate;
        this.machineIdentifiers = machineIdentifiers;
        this.applicationHash = applicationHash;
        this.ccCertificate = ccCertificate;
    }

    public LocalDateTime getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(LocalDateTime expirationDate) {
        this.expirationDate = expirationDate;
    }

    public byte[][] getMachineIdentifiers() {
        return machineIdentifiers;
    }

    public void setMachineIdentifiers(byte[][] machineIdentifiers) {
        this.machineIdentifiers = machineIdentifiers;
    }

    public byte[] getApplicationHash() {
        return applicationHash;
    }

    public void setApplicationHash(byte[] applicationHash) {
        this.applicationHash = applicationHash;
    }

    public Certificate getCcCertificate() {
        return ccCertificate;
    }

    public void setCcCertificate(Certificate ccCertificate) {
        this.ccCertificate = ccCertificate;
    }
}