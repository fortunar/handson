import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class HandsonTemplate {
    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue();
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue();




        final Agent alice = new Agent("alice", alice2bob, bob2alice, null, "AES/GCM/NoPadding") {
            @Override
            public void execute() throws Exception {
                // Alice generates privete/public key pair and sends it over the insecure channel
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(1024);
                final KeyPair aliceKP = kpg.generateKeyPair();
                outgoing.put(aliceKP.getPublic().getEncoded());

                // alice reads in Bob's key
                final X509EncodedKeySpec keySpecBob = new X509EncodedKeySpec(incoming.take());
                final RSAPublicKey bobPub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpecBob);
                print("Bobs public key: %s", hex(bobPub.getEncoded()));

                //key agreement with RSA for symmetric key (192 bits)
                final KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                final Key simKey = kg.generateKey();
                final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsaEnc.init(Cipher.ENCRYPT_MODE, bobPub);
                final byte[] simKeyCT = rsaEnc.doFinal(simKey.getEncoded());
                print("sent simkey: %s", hex(simKey.getEncoded()));
                outgoing.put(simKeyCT);

                //Perform SIGN then encrypt
                // obtain signature
                final byte[] message = "I love you Bob".getBytes();
                final Signature rsaAlice = Signature.getInstance("SHA256withRSA");
                rsaAlice.initSign(aliceKP.getPrivate());
                rsaAlice.update(message);
                final byte[] signature = rsaAlice.sign();
                // obtain ciphertext and IV
                Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, simKey);
                final byte[] iv = aes.getIV();
                //construct payload by concatenating signature and plaintext message
                final byte[] payload = ByteBuffer.allocate(signature.length + message.length)
                        .put(signature)
                        .put(message)
                        .array();
                print("Signature length: %d", signature.length);
//                outgoing.put(aes.getParameters().getEncoded());
                outgoing.put(iv);
                outgoing.put(aes.doFinal(payload));

                //DH
                //get key & parameters from bob
                final X509EncodedKeySpec keySpecDHBob = new X509EncodedKeySpec(incoming.take());
                final DHPublicKey bobDHKey = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpecDHBob);
                final DHParameterSpec dhParamSpec = bobDHKey.getParams();
                final KeyPairGenerator kpgDH = KeyPairGenerator.getInstance("DH");

                // create your own DH key pair and send to bob
                kpgDH.initialize(dhParamSpec);
                final KeyPair keyPairDH = kpgDH.generateKeyPair();
                outgoing.put(keyPairDH.getPublic().getEncoded());
                print("My contribution to DH: %s", hex(keyPairDH.getPublic().getEncoded()));

                // Run the agreement protocol
                final KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(keyPairDH.getPrivate());
                dh.doPhase(bobDHKey, true);

                // compute the shared secret
                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));

            }
        };

        final Agent bob = new Agent("bob", bob2alice, alice2bob, null, null) {
            @Override
            public void execute() throws Exception {
                // Bob generates privete/public key pair
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(1024);
                final KeyPair bobKP = kpg.generateKeyPair();
                outgoing.put(bobKP.getPublic().getEncoded());

                final X509EncodedKeySpec keySpecAlice = new X509EncodedKeySpec(incoming.take());
                final RSAPublicKey alicePub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpecAlice);
                print("Alice's public key: %s", hex(alicePub.getEncoded()));

                //key agreement with RSA for symmetric key
                final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsaEnc.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] simKeyPT = rsaEnc.doFinal(incoming.take());
                SecretKeySpec simKey = new SecretKeySpec(simKeyPT, "AES");
                print("received simkey: %s", hex(simKey.getEncoded()));

                // decrypt
//                final byte[] params = incoming.take();
                final byte[] iv = incoming.take();
                final byte[] ct = incoming.take();

//                AlgorithmParameters algParams = AlgorithmParameters.getInstance("AES/GCM/NoPadding");
//                algParams.init(params);
                Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, simKey, new GCMParameterSpec(128, iv));
                final byte[] payload = aes.doFinal(ct);
                print("received ciphertext: %s", new String(payload, "UTF-8"));
                final ByteBuffer buff = ByteBuffer.wrap(payload);

                //extract signature and payload
                final byte[] signature = new byte[128];
                buff.get(signature);
                final byte[] pt = new byte[payload.length - 128];
                buff.get(pt);
                print("plaintext: %s", new String(pt, "UTF-8"));

                //verify signature
                final Signature rsaBob = Signature.getInstance("SHA256withRSA");
                rsaBob.initVerify(alicePub);
                rsaBob.update(pt);

                if (rsaBob.verify(signature))
                    System.out.println("Valid signature.");
                else
                    System.err.println("Invalid signature.");


                //SEND A MESSAGE FROM BOB TO ALICE ALONG WITH A HMAC (exchange keys with DH)
                //generate DH keys
                final KeyPairGenerator kpgDH = KeyPairGenerator.getInstance("DH");
                kpg.initialize(2048);
                // Generate key pair
                final KeyPair keyPairDH = kpgDH.generateKeyPair();
                outgoing.put(keyPairDH.getPublic().getEncoded());
                print("My contribution to DH: %s", hex(keyPairDH.getPublic().getEncoded()));

                // get PK from bob
                final X509EncodedKeySpec aliceKeySpec = new X509EncodedKeySpec(incoming.take());
                final DHPublicKey aliceDHKey = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(aliceKeySpec);

                // Run the agreement protocol
                final KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(keyPairDH.getPrivate());
                dh.doPhase(aliceDHKey, true);

                // compute the shared secret
                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));


                final Key hmacKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
                print("HMAC key length: %d", hmacKey.getEncoded().length);

            }
        };

        // start both threads
        bob.start();
        alice.start();
    }
}
