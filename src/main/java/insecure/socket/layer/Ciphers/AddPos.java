package insecure.socket.layer.Ciphers;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AddPos implements Cipher {
    private final CipherTypes CipherType = CipherTypes.ADD_POS;

    @Override
    public byte encrypt(byte plainText, int pos) {
        return (byte) (plainText + pos);
    }

    @Override
    public byte decrypt(byte cipherText, int pos) {
        return (byte) (cipherText - pos);
    }
}
