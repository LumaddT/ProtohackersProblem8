package insecure.sockets.layer.ciphers;

public class ReverseBits implements Cipher {
    @Override
    public byte encrypt(byte plainText, int pos) {
        return (byte) (Integer.reverse(plainText) >>> 24);
    }

    @Override
    public byte decrypt(byte cipherText, int pos) {
        return encrypt(cipherText, pos);
    }

    @Override
    public String toString() {
        return "ReverseBits";
    }
}
