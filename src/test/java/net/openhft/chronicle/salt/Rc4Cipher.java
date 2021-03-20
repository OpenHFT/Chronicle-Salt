package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;

public class Rc4Cipher {

    private final int[] state;

    private final int[] key;

    public Rc4Cipher(int[] key) {
        state = new int[256];
        this.key = key;
        ksa();
    }

    private void swap(int i, int j) {
        int temp = state[i];
        state[i] = state[j];
        state[j] = temp;
    }

    private void ksa() {
        for (int i = 0; i < state.length; i++) {
            state[i] = i;
        }
        int j = 0;
        for (int i = 0; i < state.length; i++) {
            j = (j + state[i] + key[i % key.length]) % 256;
            swap(i, j);
        }
    }

    public void prga(Bytes<?> buffer, long size) {
        int i = 0;
        int j = 0;
        for (int c = 0; c < size; c++) {
            i = (i + 1) % 256;
            j = (j + state[i]) % 256;
            swap(i, j);
            buffer.writeByte((byte) state[(state[i] + state[j]) % 256]);
        }
    }
}