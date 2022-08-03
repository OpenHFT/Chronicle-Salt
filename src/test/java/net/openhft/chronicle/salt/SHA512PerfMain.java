/*
 * Copyright 2016-2022 chronicle.software
 *
 *       https://chronicle.software
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.Jvm;

import java.util.stream.IntStream;

public class SHA512PerfMain {
    static final int LENGTH = Integer.getInteger("length", 110);

    public static void main(String[] args) {
        ThreadLocal<Bytes<?>> hashBytes = ThreadLocal.withInitial(() -> Bytes.allocateDirect(SHA2.HASH_SHA512_BYTES));
        BytesStore<?, ?> bytes = Ed25519.generateRandomBytes(LENGTH);
        BytesStore<?, ?> bytes2 = Ed25519.generateRandomBytes(LENGTH);

        for (int t = 0; t < 10; t++) {
            int runs = 10_000_000;
            long start = System.nanoTime();
            IntStream.range(0, runs).parallel().forEach(i -> {
                Bytes<?> hash512 = hashBytes.get();
                hash512.writePosition(0);
                SHA2.appendSha512(hash512, bytes);
                hash512.writePosition(0);
                SHA2.appendSha512(hash512, bytes2);
            });
            long time = System.nanoTime() - start;
            System.out.printf("Throughput: %,d hashes per second%n", (long) ((2 * runs * 1e9) / time));
            Jvm.pause(100);
        }
    }
}
