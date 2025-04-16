package insecure.socket.layer.Ciphers;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class Add implements Cipher {
    private final CipherTypes CipherType = CipherTypes.ADD;

    private final byte Value;

    @Override
    public void apply(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (bytes[i] + Value);
        }
    }

    @Override
    public void applyReverse(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (bytes[i] - Value);
        }
    }
}
