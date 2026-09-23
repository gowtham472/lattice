package in.gov.identity;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AadhaarVault {
    private final SecretKeySpec vaultKey;

    public AadhaarVault(byte[] key) {
        this.vaultKey = new SecretKeySpec(key, "AES");
    }

    public byte[] sealAadhaar(String aadhaarNumber) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, vaultKey);
        return cipher.doFinal(aadhaarNumber.getBytes());
    }
}
