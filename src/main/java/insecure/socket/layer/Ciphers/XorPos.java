package insecure.socket.layer.Ciphers;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class XorPos implements Cipher {
    private final CipherTypes CipherType = CipherTypes.XOR_POS;

    @Override
    public byte encrypt(byte plainText, int pos) {
        return (byte) (plainText ^ (byte) pos);
    }

    @Override
    public byte decrypt(byte cipherText, int pos) {
        return encrypt(cipherText, pos);
    }
}
