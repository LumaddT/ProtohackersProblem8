package insecure.socket.layer.Ciphers;

public interface Cipher {
    void apply(byte[] bytes);
    void applyReverse(byte[] bytes);
}
