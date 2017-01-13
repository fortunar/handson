
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.concurrent.BlockingQueue;

/**
 * Represents an agent that can communicate with others using an ideal
 * (noiseless) communication channel.
 * <p/>
 * Agent's behavior is implemented by defining the execute method
 */
public abstract class Agent extends Thread {
    protected final BlockingQueue<byte[]> outgoing, incoming;

    protected final Key cipherKey;
    protected final String cipher;

    public Agent(final String name, final BlockingQueue<byte[]> outgoing,
                 final BlockingQueue<byte[]> incoming, final Key key, final String cipher) {
        super(name);
        this.outgoing = outgoing;
        this.incoming = incoming;
        this.cipherKey = key;
        this.cipher = cipher;
    }

    /**
     * Converts a byte[] into a string of HEX values
     *
     * @param bytes
     * @return
     */
    public String hex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    /**
     * Override this method to define agent's behavior
     *
     * @throws Exception
     */
    public abstract void execute() throws Exception;

    @Override
    public void run() {
        try {
            execute();
        } catch (Exception e) {
            print("EXCEPTION: %s", e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Prints a message to standard output. Follows the same semantics
     * as {@link System#out#printf}
     *
     * @param string
     * @param obj
     */
    public void print(String string, Object... obj) {
        System.out.printf("[%s] ", getName());
        System.out.printf(string, obj);
        System.out.println();
    }
}