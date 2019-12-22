import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;

public class SymmetricEncryptedInformation {
    private String encryptionAlgorithm;
    private String blockChainingMode;
    private String padding;
    private int iterationCount;
    private int keyLength;
    private byte[] initialVector;
    private byte[] encryptedInformation;

    public SymmetricEncryptedInformation(String encryptionAlgorithm, String blockChainingMode, String padding, int iterationCount, int keyLength) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.blockChainingMode = blockChainingMode;
        this.padding = padding;
        this.iterationCount = iterationCount;
        this.keyLength = keyLength;
        this.initialVector = null;
        this.encryptedInformation = null;
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public void setEncryptionAlgorithm(String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public String getBlockChainingMode() {
        return blockChainingMode;
    }

    public void setBlockChainingMode(String blockChainingMode) {
        this.blockChainingMode = blockChainingMode;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }

    public int getIterationCount() {
        return iterationCount;
    }

    public void setIterationCount(int iterationCount) {
        this.iterationCount = iterationCount;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    public byte[] getInitialVector() {
        return initialVector;
    }

    public void setInitialVector(byte[] initialVector) {
        this.initialVector = initialVector;
    }

    public byte[] getEncryptedInformation() {
        return encryptedInformation;
    }

    public void setEncryptedInformation(byte[] encryptedInformation) {
        this.encryptedInformation = encryptedInformation;
    }

    public SecretKey createSecretKey() {
        KeyGenerator keyFactory = null;
        try {
            keyFactory = KeyGenerator.getInstance(getEncryptionAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyFactory.init(getKeyLength());
        return keyFactory.generateKey();
    }

    public void encrypt(SecretKey secretKey, byte[] vanillaInformation) {
        try {
            Cipher encryption = Cipher.getInstance(getEncryptionAlgorithm() + "/" + getBlockChainingMode() + "/" + getPadding());
            encryption.init(Cipher.ENCRYPT_MODE, secretKey);
            AlgorithmParameters params = encryption.getParameters();
            setInitialVector(params.getParameterSpec(IvParameterSpec.class).getIV());
            setEncryptedInformation(encryption.doFinal(vanillaInformation));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidParameterSpecException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public byte[] decrypt(SecretKey secretKey) {
        byte[] decryptedInformation = null;
        try {
            Cipher decryption = Cipher.getInstance(getEncryptionAlgorithm() + "/" + getBlockChainingMode() + "/" + getPadding());
            decryption.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(getInitialVector()));
            decryptedInformation = decryption.doFinal(getEncryptedInformation());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return decryptedInformation;
    }
}
