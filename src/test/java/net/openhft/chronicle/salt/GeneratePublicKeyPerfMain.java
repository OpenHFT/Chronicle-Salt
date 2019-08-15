package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class GeneratePublicKeyPerfMain {
    public static void main(String[] args) {
        Bytes<Void> privateKey0 = Bytes.allocateDirect(Ed25519.PRIVATE_KEY_LENGTH);
        Ed25519.generatePrivateKey(privateKey0);

        int nThreads = Runtime.getRuntime().availableProcessors();
        ExecutorService es = Executors.newFixedThreadPool(nThreads);
        long[] min = {1L << 32};
        for (int i = 0; i < nThreads; i++) {
            es.execute(() -> {
                try {
                    Bytes<Void> publicKey = Ed25519.allocatePublicKey();
                    Bytes<Void> secretKey = Ed25519.allocateSecretKey();
                    int j = 0;
                    long start = System.nanoTime();
                    Bytes<Void> privateKey = Bytes.allocateDirect(Ed25519.PRIVATE_KEY_LENGTH);
                    OUTER:
                    do {
                        if (j++ == 0)
                            Ed25519.generatePrivateKey(privateKey);
                        else if (j > 32)
                            j = 0;
                        publicKey.clear();
                        secretKey.clear();
                        privateKey.addAndGetLong(0, 1);
                        Ed25519.privateToPublicAndSecret(publicKey, secretKey, privateKey);
                        for (int k = 0; k <= Ed25519.PUBLIC_KEY_LENGTH - 4; k++) {
                            long value = publicKey.readUnsignedInt(k);
                            if (value == 0) {
                                System.out.println("k= " + k);
                                break OUTER;
                            }
                        }
                    } while (true);
                    System.out.println(privateKey.toHexString());
                    System.out.println(publicKey.toHexString());
                    long time = System.nanoTime() - start;
                    System.out.printf("Took %.3f seconds%n", time / 1e9);
                } catch (Throwable t) {
                    t.printStackTrace();
                }
            });
        }
        es.shutdownNow();
    }
}
