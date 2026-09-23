package in.gov.identity;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenService {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private final KeyPair signingKeys;

    public TokenService() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        this.signingKeys = generator.generateKeyPair();
    }

    @PostMapping("/v1/citizen/token")
    public byte[] issueToken(@RequestBody String citizenId) throws Exception {
        return sign(signingKeys.getPrivate(), citizenId.getBytes());
    }

    private byte[] sign(PrivateKey key, byte[] claims) throws Exception {
        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.initSign(key);
        signer.update(claims);
        return signer.sign();
    }
}
