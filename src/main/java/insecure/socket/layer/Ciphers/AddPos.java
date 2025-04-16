package insecure.socket.layer.Ciphers;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AddPos implements Cipher {
    private final CipherTypes CipherType = CipherTypes.ADD_POS;

    private final int InitialPos;

    @Override
    public void apply(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (bytes[i] + i + InitialPos);
        }
    }

    @Override
    public void applyReverse(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (bytes[i] - i - InitialPos);
        }
    }
}
