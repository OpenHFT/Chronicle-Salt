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
