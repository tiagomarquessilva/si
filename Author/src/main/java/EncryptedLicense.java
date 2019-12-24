import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class EncryptedLicense {
    private PublicKey userPublicKey;
    private SymmetricEncryption symmetricEncryption;
    private byte[] encryptedSymmetricKey;
    private byte[] encryptedLicense;

    public EncryptedLicense(PublicKey userPublicKey, License licenseToEncrypt) {
        this.userPublicKey = userPublicKey;
        this.symmetricEncryption = new SymmetricEncryption("AES", "CBC", "PKCS5Padding", 65536, 256);
        encryptLicense(licenseToEncrypt);
    }

    public PublicKey getUserPublicKey() {
        return userPublicKey;
    }

    public void setUserPublicKey(PublicKey userPublicKey) {
        this.userPublicKey = userPublicKey;
    }

    public SymmetricEncryption getSymmetricEncryption() {
        return symmetricEncryption;
    }

    public void setSymmetricEncryption(SymmetricEncryption symmetricEncryption) {
        this.symmetricEncryption = symmetricEncryption;
    }

    public byte[] getEncryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }

    public void setEncryptedSymmetricKey(byte[] encryptedSymmetricKey) {
        this.encryptedSymmetricKey = encryptedSymmetricKey;
    }

    public byte[] getEncryptedLicense() {
        return encryptedLicense;
    }

    public void setEncryptedLicense(byte[] encryptedLicense) {
        this.encryptedLicense = encryptedLicense;
    }

    public License decryptLicense(PrivateKey privateKey){
        //decrypt symmetric key with user public key
        SecretKey symmetricKey = null;
        try {
            Cipher symmetricKeyDecryption = Cipher.getInstance("RSA");
            symmetricKeyDecryption.init(Cipher.DECRYPT_MODE, privateKey);
            symmetricKey = new SecretKeySpec(symmetricKeyDecryption.doFinal(getEncryptedSymmetricKey()), getSymmetricEncryption().getEncryptionAlgorithm());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        // decrypt license with symmetric encryption
        byte[] licenseBytes = getSymmetricEncryption().decrypt(symmetricKey);
        License license = null;
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(licenseBytes));
            license = (License) objectInputStream.readObject();
            objectInputStream.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return license;
    }

    public void encryptLicense(License licenseToEncrypt){
        // encrypt license with symmetric encryption
        SecretKey symmetricKey = getSymmetricEncryption().createSecretKey();
        getSymmetricEncryption().encrypt(symmetricKey, licenseToEncrypt.toByteArray());
        setEncryptedLicense(getSymmetricEncryption().getEncryptedInformation());

        //encrypt symmetric key with user public key
        try {
            Cipher symmetricKeyEncryption = Cipher.getInstance("RSA");
            symmetricKeyEncryption.init(Cipher.ENCRYPT_MODE, getUserPublicKey());
            setEncryptedSymmetricKey(symmetricKeyEncryption.doFinal(symmetricKey.getEncoded()));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }
}
