
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class vaje_MITM {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final Key keyDavid2Smtp = KeyGenerator.getInstance("AES").generateKey();

        final BlockingQueue<byte[]> david2mitm = new LinkedBlockingQueue();
        final BlockingQueue<byte[]> mitm2smtp = new LinkedBlockingQueue();

        final Agent david = new Agent("DAVID", david2mitm, null, keyDavid2Smtp, "AES/CTR/NoPadding") {
            @Override
            public void execute() throws Exception {
                final String message = "from: ta.david@fri.uni-lj.si\n" +
                        "to: prof.denis@fri.uni-lj.si\n\n" +
                        "Hi! Find attached <some secret stuff>!";

                final Cipher aes = Cipher.getInstance(cipher);
                aes.init(Cipher.ENCRYPT_MODE, cipherKey);
                final byte[] ct = aes.doFinal(message.getBytes("UTF-8"));
                final byte[] iv = aes.getIV();
                print("sending: '%s' (%s)", message, hex(ct));
                outgoing.put(ct);
                outgoing.put(iv);
            }
        };

        final Agent mitm = new Agent("MITM (router)", mitm2smtp, david2mitm, null, null) {
            @Override
            public void execute() throws Exception {
                final byte[] bytes = incoming.take();
                final byte[] iv = incoming.take();
                print(" IN: %s", hex(bytes));

                final String oldPrefix = "from: ta.david@fri.uni-lj.si\n" +
                        "to: prof.denis@fri.uni-lj.si\n";
                final String newPrefix = "from: ta.david@fri.uni-lj.si\n" +
                        "to: isp.student@gmail.com   \n";

                final byte[] oldBytes = oldPrefix.getBytes("UTF-8");
                final byte[] newBytes = newPrefix.getBytes("UTF-8");

                for (int i = 0; i < oldBytes.length; i++) {
                    bytes[i] = (byte) (bytes[i] ^ oldBytes[i] ^ newBytes[i]);
                }

                print("OUT: %s", hex(bytes));
                outgoing.put(bytes);
                outgoing.put(iv);
            }
        };

        final Agent smtp = new Agent("SMTP SERVER", null, mitm2smtp, keyDavid2Smtp, "AES/CTR/NoPadding") {
            @Override
            public void execute() throws Exception {
                final byte[] ct = incoming.take();
                final byte[] iv = incoming.take();
                final Cipher c = Cipher.getInstance(cipher);
                c.init(Cipher.DECRYPT_MODE, cipherKey, new IvParameterSpec(iv));

                final byte[] pt = c.doFinal(ct);
                final String message = new String(pt, "UTF-8");

                print("got: '%s' (%s)", message, hex(ct));
            }
        };

        david.start();
        mitm.start();
        smtp.start();
    }
}

