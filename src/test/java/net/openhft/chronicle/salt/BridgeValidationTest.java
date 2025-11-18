/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.chronicle.salt;

import net.openhft.chronicle.core.OS;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assume.assumeTrue;

public class BridgeValidationTest {

    @Before
    public void checkSharedLibrary() {
        assumeTrue(OS.isLinux() && Bridge.LOADED);
    }

    @Test(expected = NullPointerException.class)
    public void cryptoBoxEasyNullPointersThrowNullPointerException() {
        Bridge.crypto_box_easy(0L, 1L, 1L, 1L, 1L, 1L);
    }

    @Test(expected = IllegalArgumentException.class)
    public void cryptoBoxEasyNegativeLengthThrowsIllegalArgumentException() {
        Bridge.crypto_box_easy(1L, 1L, -1L, 1L, 1L, 1L);
    }

    @Test(expected = NullPointerException.class)
    public void cryptoBoxOpenEasyNullPointersThrowNullPointerException() {
        Bridge.crypto_box_open_easy(0L, 1L, 1L, 1L, 1L, 1L);
    }
}
