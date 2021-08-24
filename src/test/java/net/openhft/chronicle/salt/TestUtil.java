package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.internal.NativeBytesStore;

final class TestUtil {

    private TestUtil() {
    }

    static BytesStore<?, ?> nativeBytesStore(String text) {
        return NativeBytesStore.from(text);
    }

}