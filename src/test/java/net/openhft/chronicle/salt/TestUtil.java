/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.BytesStore;

import java.nio.charset.StandardCharsets;

final class TestUtil {

    private TestUtil() {
    }

    static BytesStore<?, ?> nativeBytesStore(String text) {
        return BytesStore.nativeStoreFrom(text.getBytes(StandardCharsets.UTF_8));
    }

}