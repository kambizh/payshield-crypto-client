package my.com.kambiz.hsm.connection;

import my.com.kambiz.hsm.config.PayShieldProperties;
import my.com.kambiz.hsm.exception.PayShieldException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Raw TCP socket connection to the payShield 10K HSM.
 * 
 * Protocol framing:
 * - If length-prefix is enabled: [2-byte big-endian length][message bytes]
 * - The message itself starts with the configured header (e.g., 4 ASCII chars)
 *   followed by the 2-char command code and the command-specific fields.
 * 
 * The payShield returns responses in the same framing.
 */
public class PayShieldConnection implements Closeable {

    private static final Logger log = LoggerFactory.getLogger(PayShieldConnection.class);

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final boolean lengthPrefixEnabled;
    private volatile boolean closed = false;

    public PayShieldConnection(PayShieldProperties props) {
        try {
            this.socket = new Socket();
            this.socket.setSoTimeout(props.getReadTimeoutMs());
            this.socket.setTcpNoDelay(true);
            this.socket.setKeepAlive(true);
            this.socket.connect(
                    new InetSocketAddress(props.getHost(), props.getPort()),
                    props.getConnectTimeoutMs()
            );
            this.in = new BufferedInputStream(socket.getInputStream());
            this.out = new BufferedOutputStream(socket.getOutputStream());
            this.lengthPrefixEnabled = props.isLengthPrefixEnabled();
            log.info("Connected to payShield 10K at {}:{}", props.getHost(), props.getPort());
        } catch (IOException e) {
            throw new PayShieldException("Failed to connect to payShield at "
                    + props.getHost() + ":" + props.getPort(), e);
        }
    }

    /**
     * Send a command and receive the response.
     * Thread-safety: this method is NOT thread-safe. The connection pool
     * ensures one-thread-per-connection semantics.
     */
    public byte[] sendCommand(byte[] command) {
        try {
            // Send
            if (lengthPrefixEnabled) {
                int len = command.length;
                out.write((len >> 8) & 0xFF);
                out.write(len & 0xFF);
            }
            out.write(command);
            out.flush();

            if (log.isDebugEnabled()) {
                log.debug("TX [{}] bytes: {}", command.length, bytesToHex(command));
            }

            // Receive
            byte[] response;
            if (lengthPrefixEnabled) {
                int hi = in.read();
                int lo = in.read();
                if (hi == -1 || lo == -1) {
                    throw new PayShieldException("HSM connection closed unexpectedly while reading length prefix");
                }
                int respLen = (hi << 8) | lo;
                response = in.readNBytes(respLen);
                if (response.length != respLen) {
                    throw new PayShieldException(
                            String.format("Short read from HSM: expected %d bytes, got %d", respLen, response.length));
                }
            } else {
                // No length prefix: read until socket timeout or EOF
                ByteArrayOutputStream bos = new ByteArrayOutputStream(1024);
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) != -1) {
                    bos.write(buf, 0, n);
                    if (in.available() == 0) break;
                }
                response = bos.toByteArray();
            }

            if (log.isDebugEnabled()) {
                log.debug("RX [{}] bytes: {}", response.length, bytesToHex(response));
            }

            return response;

        } catch (IOException e) {
            throw new PayShieldException("HSM communication error", e);
        }
    }

    public boolean isValid() {
        return !closed && socket.isConnected() && !socket.isClosed();
    }

    @Override
    public void close() {
        closed = true;
        try {
            socket.close();
        } catch (IOException e) {
            log.warn("Error closing HSM connection", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
