
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class HandsonPrepAssignment {
    public static void main(String[] args) throws Exception {
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue();
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue();

        final Key simkey1 = KeyGenerator.getInstance("AES").generateKey();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final Key bobPublic = bobKP.getPublic();

        final Agent alice = new Agent("alice", alice2bob, bob2alice, null, "AES/GCM/NoPadding") {
            @Override
            public void execute() throws Exception {
                final String message = "The package is in room 102";
                final byte[] bytes = message.getBytes("UTF-8");

                final Cipher encryption = Cipher.getInstance(cipher);
                encryption.init(Cipher.ENCRYPT_MODE, simkey1);
                final byte[] iv = encryption.getIV();
                final byte[] cipherText = encryption.doFinal(bytes);
                System.out.println(iv.length);
                print("Sending: '%s' (HEX: %s)", message, hex(cipherText));
                outgoing.put(iv);
                outgoing.put(cipherText);


                byte[] bobIV = incoming.take();
                byte[] bobenc = incoming.take();
                byte[] bobsign = incoming.take();

                final Signature rsaBob = Signature.getInstance("SHA256withRSA");
                rsaBob.initVerify(bobKP.getPublic());
                rsaBob.update(bobenc);
                if (rsaBob.verify(bobsign))
                    System.out.println("Valid signature.");
                else
                    System.err.println("Invalid signature.");

                final Cipher decryptionCipher = Cipher.getInstance("AES/CTR/NoPadding");
                decryptionCipher.init(Cipher.DECRYPT_MODE, simkey1, new IvParameterSpec(bobIV));
                final byte[] decryptedText = decryptionCipher.doFinal(bobenc);
                String recvMessage = new String(decryptedText, "UTF-8");
                print("Received: %s", recvMessage);
            }
        };

        final Agent bob = new Agent("bob", bob2alice, alice2bob, null, null) {
            @Override
            public void execute() throws Exception {
                byte[] iv = incoming.take();
                final byte[] bytes = incoming.take();

                final Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
                decryptionCipher.init(Cipher.DECRYPT_MODE, simkey1, new GCMParameterSpec(128, iv));
                final byte[] decryptedText = decryptionCipher.doFinal(bytes);
                String recvMessage = new String(decryptedText, "UTF-8");
                print("Received: %s", recvMessage);


                final byte[] msgbytes = "Acknowledged.".getBytes("UTF-8");
                final Cipher encryption = Cipher.getInstance("AES/CTR/NoPadding");
                encryption.init(Cipher.ENCRYPT_MODE, simkey1);
                byte[] ivE = encryption.getIV();
                final byte[] cipherText = encryption.doFinal(msgbytes);

                final Signature rsaBob = Signature.getInstance("SHA256withRSA");

                rsaBob.initSign(bobKP.getPrivate());

                rsaBob.update(cipherText);
                final byte[] podpis = rsaBob.sign();

                outgoing.put(ivE);
                outgoing.put(cipherText);
                outgoing.put(podpis);


            }
        };

        // start both threads
        bob.start();
        alice.start();
    }
}
