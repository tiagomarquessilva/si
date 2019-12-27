package license;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.time.LocalDateTime;

public class LicenseRequestParameters extends LicenseParameters{
    private PublicKey userPublicKey;

    public LicenseRequestParameters(LocalDateTime expirationDate, byte[][] machineIdentifiers, byte[] applicationHash, PublicKey userPublicKey, Certificate userCcCertificate) {
        super(expirationDate, machineIdentifiers, applicationHash, userCcCertificate);
        this.userPublicKey = userPublicKey;
    }

    public PublicKey getUserPublicKey() {
        return userPublicKey;
    }

    public void setUserPublicKey(PublicKey userPublicKey) {
        this.userPublicKey = userPublicKey;
    }
}
