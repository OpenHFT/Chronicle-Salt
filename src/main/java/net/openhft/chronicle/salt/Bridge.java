/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.chronicle.salt;

import net.openhft.chronicle.core.OS;

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
                    String destDir = OS.getTarget();
                    String osname = System.getProperty("os.name").toLowerCase();
                    String arch = System.getProperty("os.arch").toLowerCase();
                    String pattern = osname + java.io.File.separator + arch;

                    String jarFile = src.getLocation().getFile();
                    java.util.jar.JarFile jar = new java.util.jar.JarFile(jarFile);
                    java.util.Enumeration<java.util.jar.JarEntry> enumEntries = jar.entries();
                    while (enumEntries.hasMoreElements()) {
                        java.util.jar.JarEntry file = enumEntries.nextElement();

                        if (!file.getName().contains(pattern))
                            continue;

                        java.io.File f = new java.io.File(destDir + java.io.File.separator + file.getName());

                        if (!f.exists()) {
                            java.io.File parent = f.getParentFile();
                            if (parent != null) {
                                if (!parent.mkdirs() && !parent.isDirectory()) {
                                    throw new java.io.IOException("Unable to create directory " + parent);
                                }
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
                // ignore missing bridge library in the current jar
            } catch (java.io.IOException unused) {
                // ignore I/O errors while probing for bridge library
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

    public static native int crypto_box_easy(long result, long message, long length, long nonce, long publicKey, long secretKey);

    public static native int crypto_box_open_easy(long result, long ciphertext, long length, long nonce, long publicKey, long secretKey);

}
