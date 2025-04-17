package insecure.socket.layer;

import insecure.socket.layer.Ciphers.*;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class SocketHolder {
    private static final Logger logger = LogManager.getLogger();

    private final Socket Socket;
    private final InputStream InputStream;
    private final OutputStream OutputStream;

    private final List<Cipher> CipherSpec;

    private int InputStreamPosition = 0;
    private int OutputStreamPosition = 0;

    @Getter
    private volatile boolean ConnectionAlive = false;

    public SocketHolder(Socket socket, int timeout) {
        logger.info("Socket {}: Instantiating", this.hashCode());

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

        try {
            Socket.setSoTimeout(timeout);
        } catch (SocketException e) {
            this.close();
        }

        CipherSpec = readCiphers();

        if (CipherSpec == null) {
            this.close();
            return;
        }

        logger.info("Socket {}: Received cipher spec {}", this.hashCode(), CipherSpec.stream().map(Cipher::toString).collect(Collectors.joining(",")));

        if (!isCipherSpecValid()) {
            logger.info("Socket {}: Cipher spec is invalid", this.hashCode());
            this.close();
        }
    }

    private List<Cipher> readCiphers() {
        List<Cipher> ciphers = new ArrayList<>();
        while (ConnectionAlive) {
            int readInt;
            try {
                readInt = InputStream.read();
            } catch (SocketTimeoutException e) {
                continue;
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

        return null;
    }

    private Cipher parseCipher(byte cipherIdentifier) {
        try {
            return switch (cipherIdentifier) {
                case 0x01 -> new ReverseBits();
                case 0x02 -> {
                    int readInt = -1;
                    while (ConnectionAlive) {
                        try {
                            readInt = InputStream.read();
                        } catch (SocketTimeoutException e) {
                            continue;
                        }

                        break;
                    }
                    if (readInt == -1) {
                        logger.info("Socket {} sent an EOF byte while reading the xor cipher argument.", this.hashCode());
                        yield null;
                    }

                    yield new Xor((byte) readInt);
                }
                case 0x03 -> new XorPos();
                case 0x04 -> {
                    int readInt = -1;
                    while (ConnectionAlive) {
                        try {
                            readInt = InputStream.read();
                        } catch (SocketTimeoutException e) {
                            continue;
                        }

                        break;
                    }
                    if (readInt == -1) {
                        logger.info("Socket {} sent an EOF byte while reading the add cipher argument.", this.hashCode());
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

    // Not the greatest way but it's quick and it should work
    private boolean isCipherSpecValid() {
        for (byte i = 0; i < 10; i++) {
            OutputStreamPosition = i;
            if (encrypt(i) != i) {
                return true;
            }
        }

        OutputStreamPosition = 0;

        return false;
    }

    public String readLine() {
        List<Byte> decryptedBytesRead = new ArrayList<>();
        byte byteRead;

        do {
            int intRead = -1;
            while (ConnectionAlive) {
                try {
                    intRead = InputStream.read();
                } catch (SocketTimeoutException e) {
                    continue;
                } catch (IOException e) {
                    logger.info("Socket {} experienced an IOException while reading the text line. Error message: {}", this.hashCode(), e.getMessage());
                    this.close();
                    return null;
                }

                break;
            }
            if (intRead == -1) {
                logger.info("Socket {} reached EOF while reading the text line.", this.hashCode());
                this.close();
                return null;
            }

            byteRead = decrypt((byte) intRead);
            InputStreamPosition++;

            decryptedBytesRead.add(byteRead);
        }
        while (byteRead != '\n');
        byte[] decryptedBytesReadArray = new byte[decryptedBytesRead.size()];
        for (int i = 0; i < decryptedBytesRead.size(); i++) {
            decryptedBytesReadArray[i] = decryptedBytesRead.get(i);
        }

        String line = new String(decryptedBytesReadArray, StandardCharsets.US_ASCII);

        logger.info("Socket {}: Received line {}", this.hashCode(), line);

        return line;
    }

    public void sendLine(String line) {
        logger.info("Socket {}: Sent line {}", this.hashCode(), line);

        byte[] plainText = line.getBytes(StandardCharsets.US_ASCII);
        byte[] encryptedText = encrypt(plainText);

        try {
            OutputStream.write(encryptedText);
        } catch (IOException e) {
            logger.info("Socket {} experienced an IOException while sending a line. Error message: {}", this.hashCode(), e.getMessage());
            this.close();
        }
    }

    private byte decrypt(byte encryptedByte) {
        for (Cipher cipher : CipherSpec.reversed()) {
            encryptedByte = cipher.decrypt(encryptedByte, InputStreamPosition);
        }

        return encryptedByte;
    }

    private byte[] encrypt(byte[] plainText) {
        byte[] encryptedBytes = new byte[plainText.length];
        for (int i = 0; i < plainText.length; i++) {
            encryptedBytes[i] = encrypt(plainText[i]);
            OutputStreamPosition++;
        }

        return encryptedBytes;
    }

    private byte encrypt(byte encryptedByte) {
        for (Cipher cipher : CipherSpec) {
            encryptedByte = cipher.encrypt(encryptedByte, OutputStreamPosition);
        }

        return encryptedByte;
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
