package net.openhft.chronicle.salt;

import org.junit.Test;

import static junit.framework.TestCase.assertEquals;

public class InvalidBase32Test {
    @Test
    public void testAnyDigitWrongDetected() {
        for (int shift = 59; shift > 0; shift -= 5) {
            int count = 0;
            for (int i = 0; i < 32; i++) {
                long value = (long) i << shift;
                if (value % 37 == 0)
                    count++;
            }
            // usually 1 possibly 0, never > 1
            if (count != 0)
                assertEquals(1, count);
        }
    }
}
