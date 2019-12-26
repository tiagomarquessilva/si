package cryptography;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class HybridEncryption implements Serializable {
    private PublicKey publicKey;
    private SymmetricEncryption symmetricEncryption;
    private byte[] encryptedSymmetricKey;
    private byte[] encryptedInformation;

    public HybridEncryption(PublicKey publicKey) {
        this.publicKey = publicKey;
        this.symmetricEncryption = new SymmetricEncryption("AES", "CBC", "PKCS5Padding", 65536, 256);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
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

    public byte[] getEncryptedInformation() {
        return encryptedInformation;
    }

    public void setEncryptedInformation(byte[] encryptedInformation) {
        this.encryptedInformation = encryptedInformation;
    }

    public byte[] decrypt(PrivateKey privateKey){
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
        return getSymmetricEncryption().decrypt(symmetricKey);
        /*
        License license = null;
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(licenseBytes));
            license = (License) objectInputStream.readObject();
            objectInputStream.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return license;
         */
    }

    public void encrypt(byte[] vanillaInformation){
        // encrypt license with symmetric encryption
        SecretKey symmetricKey = getSymmetricEncryption().createSecretKey();
        getSymmetricEncryption().encrypt(symmetricKey, vanillaInformation);
        setEncryptedInformation(getSymmetricEncryption().getEncryptedInformation());

        //encrypt symmetric key with user public key
        try {
            Cipher symmetricKeyEncryption = Cipher.getInstance("RSA");
            symmetricKeyEncryption.init(Cipher.ENCRYPT_MODE, getPublicKey());
            setEncryptedSymmetricKey(symmetricKeyEncryption.doFinal(symmetricKey.getEncoded()));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }
}
