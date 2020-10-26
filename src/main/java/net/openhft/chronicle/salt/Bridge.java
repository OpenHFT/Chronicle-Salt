/*
 * Copyright 2016-2020 chronicle.software
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package net.openhft.chronicle.salt;

import java.lang.reflect.Field;
import java.net.URL;
import java.security.CodeSource;

/**
 * The current versions of JNR-FFI (2.1.7-9 at least) have a bug whereby the 6th argument in a function call is getting corrupted. This
 * breaks the secret key address in the easy-box calls to libsodium. (All other functions used in libsodium are &gt; 6 args) For the time
 * being, switch to JNI for the two easy-box calls.
 * <p>
 * See https://github.com/OpenHFT/Chronicle-Salt/issues/13
 */

public class Bridge {
    public static final boolean LOADED;

    static {
        boolean loaded = false;
        try {
            try {
                // unpack .so from jar to tmpdir/os/arch
                CodeSource src = Bridge.class.getProtectionDomain().getCodeSource();
                if (src != null) {
                    String destDir = System.getProperty("java.io.tmpdir");
                    String osname = System.getProperty("os.name").toLowerCase();
                    String arch = System.getProperty("os.arch").toLowerCase();
                    String pattern = osname + java.io.File.separator + arch;

                    String jarFile = src.getLocation().getFile();
                    java.util.jar.JarFile jar = new java.util.jar.JarFile(jarFile);
                    java.util.Enumeration enumEntries = jar.entries();
                    while (enumEntries.hasMoreElements()) {
                        java.util.jar.JarEntry file = (java.util.jar.JarEntry) enumEntries.nextElement();

                        if (!file.getName().contains(pattern))
                            continue;

                        java.io.File f = new java.io.File(destDir + java.io.File.separator + file.getName());

                        if (!f.exists()) {
                            java.io.File parent = f.getParentFile();
                            if (parent != null) {
                                parent.mkdirs();
                                f = new java.io.File(destDir + java.io.File.separator + file.getName());
                            }
                        }

                        if (file.isDirectory()) { // if its a directory, create it
                            continue;
                        }

                        System.out.println("Unpacking " + file.getName() + " to " + f.toString());

                        java.io.InputStream is = jar.getInputStream(file); // get the input stream
                        java.io.FileOutputStream fos = new java.io.FileOutputStream(f);
                        while (is.available() > 0) { // write contents of 'is' to 'fos'
                            fos.write(is.read());
                        }
                        fos.close();
                        is.close();
                    }
                    jar.close();

                    // update java.library.path to include tmpdir/os/arch
                    // Note, java.library.path is cached by the JVM at startup, so force via reflective access
                    // This may be an issue with Java 10+
                    // See
                    // https://stackoverflow.com/questions/5419039/is-djava-library-path-equivalent-to-system-setpropertyjava-library-path
                    String libpath = System.getProperty("java.library.path");
                    libpath = libpath + java.io.File.pathSeparator + destDir + java.io.File.separator + pattern;

                    try {
                        System.setProperty("java.library.path", libpath);
                        Field fieldSysPath = ClassLoader.class.getDeclaredField("sys_paths");
                        fieldSysPath.setAccessible(true);
                        fieldSysPath.set(null, null);
                    } catch (java.lang.IllegalAccessException e) {
                        // ignored
                    } catch (java.lang.NoSuchFieldException e) {
                        // ignored
                    }
                }
            } catch (java.io.FileNotFoundException unused) {
            } catch (java.io.IOException unused) {
            }

            try {
                URL url = Bridge.class.getClassLoader().getResource("libbridge.so");
                if (url != null) {
                    System.load(url.getFile());
                    loaded = true;
                }
            } catch (Exception e) {
                // ignored.
            }
            if (!loaded) {
                System.loadLibrary("bridge");
            }

            loaded = true;
        } catch (UnsatisfiedLinkError ule) {
            loaded = false;
        }

        LOADED = loaded;
    }

    public native static int crypto_box_easy(long result, long message, long length, long nonce, long publicKey, long secretKey);

    public native static int crypto_box_open_easy(long result, long ciphertext, long length, long nonce, long publicKey, long secretKey);

}
