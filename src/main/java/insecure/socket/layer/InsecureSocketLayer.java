package insecure.socket.layer;

import insecure.socket.layer.exceptions.IllegalMessageException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

public class InsecureSocketLayer {
    private static final Logger logger = LogManager.getLogger();

    private static final int TIMEOUT = 1_000;
    private static final int MAX_LENGTH = 5_000;

    private static volatile boolean Running = false;

    public static void run(int port) {
        if (Running) {
            logger.warn("Attempted to run, but this is already running.");
            return;
        }

        Running = true;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.info("Started on port {}.", port);

            serverSocket.setSoTimeout(TIMEOUT);

            while (Running) {
                try {
                    Socket socket = serverSocket.accept();
                    new Thread(() -> manageSocket(socket)).start();
                } catch (SocketTimeoutException e) {
                    logger.trace("Socket timed out (timeout: {}) in thread {}.", TIMEOUT, Thread.currentThread().toString());
                }
            }
        } catch (IOException e) {
            logger.fatal("An IO exception was thrown by the SocketServer. No attempt will be made to reopen the socket.\n{}\n{}", e.getMessage(), e.getStackTrace());
        }
    }

    private static void manageSocket(Socket socket) {
        InputStream inputStream;
        OutputStream outputStream;

        try {
            inputStream = socket.getInputStream();
            outputStream = socket.getOutputStream();
        } catch (IOException e) {
            logger.debug("An error occurred wile obtaining Input and Output streams for for a Socket. The Socket will be discarded.");
            return;
        }

        byte[] clientBytes;
        try {
            clientBytes = readMessage(inputStream);
        } catch (IllegalMessageException illegalMessageException) {
            logger.info("A client sent an illegal message. Error message: {}", illegalMessageException.getMessage());
            try {
                socket.close();
            } catch (IOException ioException) {
                logger.debug("(Error closed) An error occurred while trying to close a Socket. Error message: {}", ioException.getMessage());
            }

            return;
        }

        if (clientBytes == null) {
            logger.debug("The client gracefully closed the connection.");
            try {
                socket.close();
            } catch (IOException ioException) {
                logger.debug("(Gracefully closed) An error occurred while trying to close a Socket. Error message: {}", ioException.getMessage());
            }

            return;
        }
    }

    private static byte[] readMessage(InputStream inputStream) throws IllegalMessageException {
        byte[] buffer = new byte[MAX_LENGTH];
        int i = 0;

        while (i < MAX_LENGTH) {
            int readInt;
            try {
                readInt = inputStream.read();
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

    public static void stop() {
        if (Running) {
            logger.info("Stopped.");
        } else {
            logger.warn("Attempted to stop, but this is already stopped.");
        }
        Running = false;
    }
}
