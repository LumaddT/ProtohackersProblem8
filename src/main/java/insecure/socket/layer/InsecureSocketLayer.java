package insecure.socket.layer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InsecureSocketLayer {
    private static final Logger logger = LogManager.getLogger();

    private static final int TIMEOUT = 1_000;
    private static final String REGEX = "^(\\d+)x .+$";
    private static final Pattern PATTERN = Pattern.compile(REGEX);

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
        SocketHolder socketHolder = new SocketHolder(socket, 1_000);

        while (Running && socketHolder.isConnectionAlive()) {
            String line = socketHolder.readLine();

            if (line == null) {
                logger.error("Socket {} returned a null line.", socketHolder.hashCode());
                socketHolder.close();
                return;
            }

            String[] lineSplit = line.split(",");

            String maxToy = null;
            int maxValue = Integer.MIN_VALUE;

            for (String toy : lineSplit) {
                toy = toy.trim();
                Matcher matcher = PATTERN.matcher(toy);
                if (matcher.find()) {
                    String amountString = matcher.group(1);
                    int amount = Integer.parseInt(amountString);
                    if (amount > maxValue) {
                        maxValue = amount;
                        maxToy = toy;
                    }
                } else {
                    logger.error("Toy \"{}\" in line \"{}\" did not match the regex.", toy, line);
                }
            }

            if (maxToy == null) {
                logger.error("Did not find a max toy in line \"{}\".", line);
                socketHolder.close();
                return;
            }
            socketHolder.sendLine(maxToy + '\n');
        }
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
