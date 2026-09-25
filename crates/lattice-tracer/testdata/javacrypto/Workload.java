// A workload for testing LATTICE's Java tracing: each algorithm is used once, then a TLS 1.3
// handshake runs over loopback. It waits first, so a recording can start before it works.
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class Workload {
    public static void main(String[] args) throws Exception {
        Thread.sleep(Long.parseLong(args.length > 1 ? args[1] : "0"));

        KeyGenerator aes = KeyGenerator.getInstance("AES");
        aes.init(256);
        SecretKey key = aes.generateKey();
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
        gcm.doFinal("hello".getBytes());

        Cipher ecb = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        ecb.init(Cipher.ENCRYPT_MODE, KeyGenerator.getInstance("DESede").generateKey());
        ecb.doFinal("hello".getBytes());

        MessageDigest.getInstance("MD5").digest("a".getBytes());
        MessageDigest.getInstance("SHA-1").digest("a".getBytes());

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(1024);
        KeyPair rsaPair = rsa.generateKeyPair();
        Signature signing = Signature.getInstance("SHA256withRSA");
        signing.initSign(rsaPair.getPrivate());
        signing.update("m".getBytes());
        signing.sign();
        Cipher oaep = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        oaep.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        oaep.doFinal("k".getBytes());

        KeyPairGenerator x25519 = KeyPairGenerator.getInstance("X25519");
        KeyPair a = x25519.generateKeyPair(), b = x25519.generateKeyPair();
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(a.getPrivate());
        agreement.doPhase(b.getPublic(), true);
        agreement.generateSecret();

        KeyPair mlkem = KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
        KEM.getInstance("ML-KEM").newEncapsulator(mlkem.getPublic()).encapsulate();

        // TLS 1.3 over loopback with the keystore made by keytool
        char[] password = "changeit".toCharArray();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(args[0])) {
            store.load(in, password);
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, password);
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(store);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
        try (SSLServerSocket server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0)) {
            Thread serving = new Thread(() -> {
                try (SSLSocket connection = (SSLSocket) server.accept()) {
                    connection.getInputStream().read();
                } catch (Exception ignored) {
                }
            });
            serving.start();
            try (SSLSocket client = (SSLSocket) context.getSocketFactory().createSocket("localhost", server.getLocalPort())) {
                client.startHandshake();
                OutputStream out = client.getOutputStream();
                out.write(1);
                out.flush();
                System.out.println("tls " + client.getSession().getProtocol() + " " + client.getSession().getCipherSuite());
            }
            serving.join();
        }
        Thread.sleep(Long.parseLong(args.length > 2 ? args[2] : "0"));
    }
}
