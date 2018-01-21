package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;

public interface Crypto {
    /**
     * Initialise the bytes so that a message can be written and signed later.
     *
     * @param bytes to pad so it can be written to.
     */
    void initialiseForWrite(Bytes bytes);

    void generateKey(Bytes<?> privateKey, Bytes<?> publicKey);

    void sign(BytesStore bytes, BytesStore privateKey);

    boolean verify(BytesStore bytes, BytesStore publicKey);
}
