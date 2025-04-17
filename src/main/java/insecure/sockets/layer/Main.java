package insecure.sockets.layer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Main {
    private static final Logger logger = LogManager.getLogger();

    public static void main(String[] args) {
        logger.info("Starting up...");

        Runtime.getRuntime().addShutdownHook(new Thread(Main::shutdownRoutine));

        new Thread(() -> InsecureSocketsLayer.run(10_008)).start();
    }

    private static void shutdownRoutine() {
        logger.info("Shutting down...");

        InsecureSocketsLayer.stop();

        logger.info("Have a nice day!.");
    }
}
