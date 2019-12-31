import cryptography.HybridEncryption;
import cryptography.PasswordBasedEncryption;
import license.LicenseRequest;
import license.LicenseRequestParameters;
import oshi.SystemInfo;
import oshi.hardware.ComputerSystem;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.hardware.NetworkIF;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class Library {
    HybridEncryption encryptedLicense;
    PasswordBasedEncryption encryptedUserPrivateKey;
    PublicKey userPublicKey;

    // +===+ Helper Methods +===+
    private byte[] hashInformation(byte[] information){
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

    // +======+
    // +===+ Class Methods +===+

    public byte[][] getMachineIdentifiers(){
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

    public byte[] getApplicationHash(){

    }

    public boolean isRegistered() {
        return true;
    }

    public boolean startRegistration() {
        LicenseRequest licenseRequest = new LicenseRequest(new LicenseRequestParameters(getMachineIdentifiers(), ), );
        return true;
    }

    public void showLicenseInfo() {

    }
    // +======+
}
