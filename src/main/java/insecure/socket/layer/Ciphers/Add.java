package insecure.socket.layer.Ciphers;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class Add implements Cipher {
    private final CipherTypes CipherType = CipherTypes.ADD;

    private final byte Value;

    @Override
    public byte encrypt(byte plainText, int pos) {
        return (byte) (plainText + pos);

    }

    @Override
    public byte decrypt(byte cipherText, int pos) {
        return (byte) (cipherText - pos);
    }

    @Override
    public String toString() {
        return "Add(0x%02Xd)".formatted(Value);
    }
}
