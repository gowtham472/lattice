import java.security.KeyPairGenerator;
import javax.crypto.Cipher;

final class PaymentCrypto {
    private PaymentCrypto() {}

    static KeyPairGenerator signingKeys() throws Exception {
        return KeyPairGenerator.getInstance("RSA");
    }

    static Cipher cardCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
