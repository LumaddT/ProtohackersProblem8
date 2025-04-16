package insecure.socket.layer.Ciphers;

import lombok.Getter;

@Getter
public enum CipherTypes {
    END((byte) 0x00),
    REVERSE_BITS((byte) 0x01),
    XOR((byte) 0x02),
    XOR_POS((byte) 0x03),
    ADD((byte) 0x04),
    ADD_POS((byte) 0x05);

    private final byte Encoding;

    CipherTypes(byte encoding) {
        Encoding = encoding;
    }
}
