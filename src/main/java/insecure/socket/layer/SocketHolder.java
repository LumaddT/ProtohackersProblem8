package insecure.socket.layer;

import insecure.socket.layer.Ciphers.*;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SocketHolder {
    private static final Logger logger = LogManager.getLogger();

    private static final int MAX_LENGTH = 5_000;

    private final Socket Socket;
    private final InputStream InputStream;
    private final OutputStream OutputStream;

    private final List<Cipher> CipherSpec;

    private int inputStreamPosition = 0;
    private int outputCounter = 0;

    @Getter
    private volatile boolean ConnectionAlive = false;

    public SocketHolder(Socket socket) {
        Socket = socket;

        InputStream inputStream;
        OutputStream outputStream;

        try {
            inputStream = socket.getInputStream();
            outputStream = socket.getOutputStream();

            ConnectionAlive = true;
        } catch (IOException e) {
            logger.debug("An error occurred wile obtaining Input and Output streams for for a Socket. The Socket will be discarded.");
            inputStream = null;
            outputStream = null;

            this.close();
        }

        InputStream = inputStream;
        OutputStream = outputStream;

        CipherSpec = readCiphers();

        if (!isCipherSpecValid()) {
            this.close();
        }
    }

    private List<Cipher> readCiphers() {
        List<Cipher> ciphers = new ArrayList<>();
        while (true) {
            int readInt;
            try {
                readInt = InputStream.read();
            } catch (IOException e) {
                logger.info("Socket {} experienced an IOException while reading the cipher spec. Error message: {}", this.hashCode(), e.getMessage());
                return null;
            }

            if (readInt == -1) {
                logger.info("Socket {} send an EOF byte while reading the cipher spec.", this.hashCode());
                return null;
            }

            if (readInt == 0) {
                return Collections.unmodifiableList(ciphers);
            }

            Cipher newCipher = parseCipher((byte) readInt);

            if (newCipher == null) {
                return null;
            }

            ciphers.add(newCipher);
        }
    }

    private Cipher parseCipher(byte cipherIdentifier) {
        try {
            return switch (cipherIdentifier) {
                case 0x01 -> new ReverseBits();
                case 0x02 -> {
                    int readInt = InputStream.read();
                    if (readInt == -1) {
                        logger.info("Socket {} send an EOF byte while reading the xor cipher argument.", this.hashCode());
                        yield null;
                    }

                    yield new Xor((byte) readInt);
                }
                case 0x03 -> new XorPos();
                case 0x04 -> {
                    int readInt = InputStream.read();
                    if (readInt == -1) {
                        logger.info("Socket {} send an EOF byte while reading the add cipher argument.", this.hashCode());
                        yield null;
                    }

                    yield new Add((byte) readInt);
                }
                case 0x05 -> new AddPos();
                // This should never happen
                default -> throw new RuntimeException("The client send an illegal cipher spec.");
            };
        } catch (IOException e) {
            logger.info("Socket {} experienced an IOException while reading a cipher argument. Error message: {}", this.hashCode(), e.getMessage());
            return null;
        }
    }

    private boolean isCipherSpecValid() {
        // TODO
        return true;
    }

    public void close() {
        logger.info("Closing socket {}.", this.hashCode());
        ConnectionAlive = false;

        try {
            Socket.shutdownInput();
            Socket.shutdownOutput();

            Socket.close();
        } catch (IOException ex) {
            logger.debug("An error occurred while attempting to close the Socket {}.", this.hashCode());
        }
    }
}
