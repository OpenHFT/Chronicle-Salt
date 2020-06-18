/* vim: syntax=cpp
 * Copyright 2015 Higher Frequency Trading
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NET_OPENHFT_CHRONICLE_SALT_BRIDGE_H
#define NET_OPENHFT_CHRONICLE_SALT_BRIDGE_H

#include <jni.h>
#include "net_openhft_chronicle_salt_Bridge.h"

#include <sodium.h>

/**
 *  JNI interface
 */
JNIEXPORT jint JNICALL Java_net_openhft_chronicle_salt_Bridge_crypto_1box_1easy
  (JNIEnv * env, jclass obj, jlong result, jlong message, jlong length, jlong nonce, jlong publicKey, jlong secretKey)
{
    return (jint)crypto_box_easy( (unsigned char*)result,
                                  (const unsigned char*)message,
                                  (unsigned long long)length,
                                  (const unsigned char*)nonce,
                                  (const unsigned char*)publicKey,
                                  (const unsigned char*)secretKey );
}

JNIEXPORT jint JNICALL Java_net_openhft_chronicle_salt_Bridge_crypto_1box_1open_1easy
  (JNIEnv * env, jclass obj, jlong result, jlong ciphertext, jlong length, jlong nonce, jlong publicKey, jlong secretKey)
{
    return (jint)crypto_box_open_easy( (unsigned char*)result,
                                       (const unsigned char*)ciphertext,
                                       (unsigned long long)length,
                                       (const unsigned char*)nonce,
                                       (const unsigned char*)publicKey,
                                       (const unsigned char*)secretKey );
}

#endif
