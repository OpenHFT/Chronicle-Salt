/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
/**
 * Cryptographic primitives built on top of libsodium.
 * <p>
 * This package exposes high-level Java wrappers for selected hashing,
 * signature and box operations, such as Blake2b, Ed25519 and sealed
 * boxes. Implementations delegate to the underlying native library via
 * the {@code Sodium} bridge where available.
 * <p>
 * The API is intended for latency-sensitive systems that require
 * explicit control over allocation and key handling. Callers are
 * responsible for managing keys and verifying that chosen primitives
 * meet their security requirements.
 */
package net.openhft.chronicle.salt;

