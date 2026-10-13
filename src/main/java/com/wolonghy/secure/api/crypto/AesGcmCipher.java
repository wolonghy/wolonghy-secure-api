/*
 * Copyright 2026 Beijing Wolong Huiyan Technology Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.wolonghy.secure.api.crypto;

import com.wolonghy.secure.api.exception.SecureApiException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AES-256-GCM authenticated encryption and decryption.
 *
 * <p>AES-GCM provides both confidentiality and integrity (authentication tag),
 * making it the recommended choice for symmetric encryption in modern applications.</p>
 *
 * <p>The ciphertext format is: {@code [12-byte IV] + [encrypted data + auth tag]}.</p>
 *
 * <pre>{@code
 * byte[] key = AesGcmCipher.generateKey();
 * byte[] ciphertext = AesGcmCipher.encrypt(key, plaintext);
 * byte[] decrypted = AesGcmCipher.decrypt(key, ciphertext);
 * }</pre>
 *
 * @author Zhang Ze
 * @since 1.0.0
 */
public final class AesGcmCipher {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int KEY_LENGTH_BYTE = 32;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private AesGcmCipher() {
    }

    /**
     * Encrypts data using AES-256-GCM with a randomly generated IV.
     *
     * @param key  the 32-byte (256-bit) secret key
     * @param data the plaintext data to encrypt
     * @return the ciphertext in the format: IV + encrypted data + auth tag
     * @throws SecureApiException if encryption fails
     * @throws IllegalArgumentException if the key is null or not 32 bytes
     */
    public static byte[] encrypt(byte[] key, byte[] data) {
        validateKey(key);
        if (data == null) {
            throw new IllegalArgumentException("Data must not be null");
        }
        try {
            byte[] iv = new byte[IV_LENGTH_BYTE];
            SECURE_RANDOM.nextBytes(iv);

            SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            byte[] ciphertext = cipher.doFinal(data);

            byte[] result = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
            return result;
        } catch (Exception e) {
            throw new SecureApiException("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypts AES-256-GCM ciphertext (automatically extracts IV and verifies auth tag).
     *
     * @param key           the 32-byte (256-bit) secret key
     * @param encryptedData the ciphertext in the format: IV + encrypted data + auth tag
     * @return the decrypted plaintext bytes
     * @throws SecureApiException if the encrypted data is too short, authentication fails,
     *                            or the data has been tampered with
     * @throws IllegalArgumentException if the key or encrypted data is null, or key length is not 32 bytes
     */
    public static byte[] decrypt(byte[] key, byte[] encryptedData) {
        validateKey(key);
        if (encryptedData == null) {
            throw new IllegalArgumentException("Encrypted data must not be null");
        }
        if (encryptedData.length < IV_LENGTH_BYTE) {
            throw new SecureApiException("Encrypted data is too short to contain a valid IV");
        }
        try {
            byte[] iv = new byte[IV_LENGTH_BYTE];
            System.arraycopy(encryptedData, 0, iv, 0, IV_LENGTH_BYTE);

            byte[] ciphertext = new byte[encryptedData.length - IV_LENGTH_BYTE];
            System.arraycopy(encryptedData, IV_LENGTH_BYTE, ciphertext, 0, ciphertext.length);

            SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new SecureApiException("AES-GCM decryption failed (data may have been tampered with)", e);
        }
    }

    /**
     * Generates a random 32-byte (256-bit) AES key.
     *
     * @return a new random key
     */
    public static byte[] generateKey() {
        byte[] key = new byte[KEY_LENGTH_BYTE];
        SECURE_RANDOM.nextBytes(key);
        return key;
    }

    /**
     * Returns the required key length in bytes (32 bytes for AES-256).
     *
     * @return the key length in bytes
     */
    public static int getKeyLength() {
        return KEY_LENGTH_BYTE;
    }

    private static void validateKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("Key must not be null");
        }
        if (key.length != KEY_LENGTH_BYTE) {
            throw new IllegalArgumentException(
                    "Key must be " + KEY_LENGTH_BYTE + " bytes (AES-256), but was " + key.length + " bytes");
        }
    }
}
