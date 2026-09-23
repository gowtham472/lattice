package in.gov.identity;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

public class DeviceAttestation {
    public KeyPairGenerator deviceKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator;
    }
}
