package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.Jvm;

import java.util.stream.IntStream;

public class SHA512PerfMain {
    static final int LENGTH = Integer.getInteger("length", 110);

    public static void main(String[] args) {

        ThreadLocal<Bytes> hashBytes = ThreadLocal.withInitial(() -> Bytes.allocateDirect(SHA2.HASH_SHA512_BYTES));
        BytesStore bytes = Ed25519.generateRandomBytes(LENGTH);
        BytesStore bytes2 = Ed25519.generateRandomBytes(LENGTH);

        for (int t = 0; t < 10; t++) {
            int runs = 10_000_000;
            long start = System.nanoTime();
            IntStream.range(0, runs).parallel().forEach(i -> {
                Bytes hash512 = hashBytes.get();
                SHA2.sha512(hash512, bytes);
                SHA2.sha512(hash512, bytes2);
            });
            long time = System.nanoTime() - start;
            System.out.printf("Throughput: %,d hashes per second%n", (long) (2 * runs * 1e9 / time));
            Jvm.pause(100);
        }
    }
}
