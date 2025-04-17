package insecure.sockets.layer.ciphers;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class Add implements Cipher {
    private final byte Value;

    @Override
    public byte encrypt(byte plainText, int pos) {
        return (byte) (plainText + Value);

    }

    @Override
    public byte decrypt(byte cipherText, int pos) {
        return (byte) (cipherText - Value);
    }

    @Override
    public String toString() {
        return "Add(0x%02X)".formatted(Value);
    }
}
