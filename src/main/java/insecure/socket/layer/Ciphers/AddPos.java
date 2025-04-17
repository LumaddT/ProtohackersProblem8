package insecure.socket.layer.Ciphers;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AddPos implements Cipher {
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
        return "AddPos";
    }

}
