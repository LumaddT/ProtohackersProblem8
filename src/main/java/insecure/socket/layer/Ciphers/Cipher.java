package insecure.socket.layer.Ciphers;

public interface Cipher {
    byte encrypt(byte plainText, int pos);

    byte decrypt(byte cipherText, int pos);
}
