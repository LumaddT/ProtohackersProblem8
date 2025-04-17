package insecure.socket.layer.Ciphers;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class XorPos implements Cipher {
    @Override
    public byte encrypt(byte plainText, int pos) {
        return (byte) (plainText ^ (byte) pos);
    }

    @Override
    public byte decrypt(byte cipherText, int pos) {
        return encrypt(cipherText, pos);
    }

    @Override
    public String toString() {
        return "XorPos";
    }
}
