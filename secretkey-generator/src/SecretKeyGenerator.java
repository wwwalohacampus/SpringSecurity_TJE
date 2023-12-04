import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;

public class SecretKeyGenerator {

    public static Key generateSecretKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecureRandom secureRandom = new SecureRandom();
            keyGenerator.init(secureRandom);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate secret key", e);
        }
    }

    public static void main(String[] args) {
        Key secretKey = generateSecretKey();
        System.out.println("Generated Secret Key: " + secretKey);
    }
}
