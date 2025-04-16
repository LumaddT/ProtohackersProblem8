package insecure.socket.layer.Ciphers;

public class ReverseBits implements Cipher {
    private final CipherTypes CipherType = CipherTypes.REVERSE_BITS;

    @Override
    public void apply(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (Integer.reverse(bytes[i]) >>> 24);
        }
    }

    @Override
    public void applyReverse(byte[] bytes) {
        this.apply(bytes);
    }
}
