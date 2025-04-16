package insecure.socket.layer;

import insecure.socket.layer.exceptions.IllegalMessageException;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class SocketHolder {
    private static final Logger logger = LogManager.getLogger();

    private static final int MAX_LENGTH = 5_000;

    private final Socket Socket;
    private final InputStream InputStream;
    private final OutputStream OutputStream;

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
    }

    // TODO: parse and return message
    private void readMessage() {
        byte[] clientBytes;
        try {
            clientBytes = readBytes();
        } catch (IllegalMessageException illegalMessageException) {
            logger.info("A client sent an illegal message. Error message: {}", illegalMessageException.getMessage());
            this.close();
            return;
        }

        if (clientBytes == null) {
            logger.debug("The client gracefully closed the connection.");
            this.close();
            return;
        }
    }

    private byte[] readBytes() throws IllegalMessageException {
        byte[] buffer = new byte[MAX_LENGTH];
        int i = 0;

        while (i < MAX_LENGTH) {
            int readInt;
            try {
                readInt = InputStream.read();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            if (readInt == -1) {
                if (i > 0) {
                    throw new IllegalMessageException("The client sent EOF before completing the message.");
                }

                return null;
            }

            byte readByte = (byte) readInt;

            buffer[i] = readByte;
            if (readByte == '\n') {
                return buffer;
            }

            i++;
        }

        throw new IllegalMessageException("The client sent a message too long.");
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
