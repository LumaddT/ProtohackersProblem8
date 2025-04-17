package insecure.socket.layer.Ciphers;

public class ReverseBits implements Cipher {
    private final CipherTypes CipherType = CipherTypes.REVERSE_BITS;

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
