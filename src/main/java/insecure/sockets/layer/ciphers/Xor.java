package insecure.sockets.layer.ciphers;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class Xor implements Cipher {
    private final byte Value;

    @Override
    public byte encrypt(byte plainText, int pos) {
        return (byte) (plainText ^ Value);
    }

    @Override
    public byte decrypt(byte cipherText, int pos) {
        return encrypt(cipherText, pos);
    }

    @Override
    public String toString() {
        return "Xor(0x%02X)".formatted(Value);
    }
}
