package insecure.socket.layer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Main {
    private static final Logger logger = LogManager.getLogger();

    public static void main(String[] args) {
        logger.info("Starting up...");

        Runtime.getRuntime().addShutdownHook(new Thread(Main::shutdownRoutine));

        new Thread(() -> InsecureSocketLayer.run(10_008)).start();
    }

    private static void shutdownRoutine() {
        logger.info("Shutting down...");

        InsecureSocketLayer.stop();

        logger.info("Have a nice day!.");
    }
}
