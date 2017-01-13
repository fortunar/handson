

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class vaje_DH {
    public static void main(String[] args) throws Exception {

        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue();
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue();

        final Agent alice = new Agent("alice", alice2bob, bob2alice, null, "AES/GCM/NoPadding") {
            @Override
            public void execute() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
                kpg.initialize(2048);

                // Generate key pair
                final KeyPair keyPair = kpg.generateKeyPair();

                // send "PK" to bob ("PK": A = g^a, "SK": a)
//                outgoing.put(keyPair.getPublic().getEncoded());
//                print("My contribution to DH: %s", hex(keyPair.getPublic().getEncoded()));

                KeyFactory kf = KeyFactory.getInstance("DH");
                outgoing.put(kf.getKeySpec(keyPair.getPublic() ,PKCS8EncodedKeySpec.class).getEncoded());


                // get PK from bob
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(incoming.take());
                final DHPublicKey bobPK = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpec);

                // Run the agreement protocol
                final KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(bobPK, true);

                // generate a shared AES key
                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));

                // By default the shared secret will be 32 bytes long,
                // Uur cipher requires keys of length 16 bytes
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Cipher aes = Cipher.getInstance(cipher);
                aes.init(Cipher.ENCRYPT_MODE, aesKey);

                final byte[] ct = aes.doFinal("Hey Bob!".getBytes("UTF-8"));
                final byte[] iv = aes.getIV();

                outgoing.put(iv);
                outgoing.put(ct);

                print("I'm, done!");
            }
        };

        final Agent bob = new Agent("bob", bob2alice, alice2bob, null, "AES/GCM/NoPadding") {
            @Override
            public void execute() throws Exception {
                // get PK from alice
                final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(incoming.take());
                final DHPublicKey alicePK = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpec);

                final DHParameterSpec dhParamSpec = alicePK.getParams();

                // create your own DH key pair
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
                kpg.initialize(dhParamSpec);
                final KeyPair keyPair = kpg.generateKeyPair();
                outgoing.put(keyPair.getPublic().getEncoded());
                print("My contribution to DH: %s", hex(keyPair.getPublic().getEncoded()));

                final KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(alicePK, true);

                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                final Cipher aes = Cipher.getInstance(cipher);
                final byte[] iv = incoming.take();
                final byte[] ct = incoming.take();
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] pt = aes.doFinal(ct);

                print("I got: %s", new String(pt, "UTF-8"));
            }
        };

        alice.start();
        bob.start();
    }
}
