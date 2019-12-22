import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;

public class PasswordEncryptedInformation extends SymmetricEncryptedInformation {
    private byte[] salt;

    public PasswordEncryptedInformation(String encryptionAlgorithm, String blockChainingMode, String padding, int iterationCount, int keyLength) {
        super(encryptionAlgorithm, blockChainingMode, padding, iterationCount, keyLength);
        this.salt = createSalt();
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public byte[] createSalt() {
        Random randomInts = new SecureRandom();
        byte[] salt = new byte[32];
        randomInts.nextBytes(salt);
        return salt;
    }

    public SecretKey createSecretKey(char[] password) {
        SecretKey secretKey = null;
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(password, getSalt(), getIterationCount(), getKeyLength());
             secretKey = keyFactory.generateSecret(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            e.printStackTrace();
        }
        assert secretKey != null;
        return new SecretKeySpec(secretKey.getEncoded(), getEncryptionAlgorithm());
    }
}
