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
package com.wolonghy.secure.api;

import com.wolonghy.secure.api.codec.Base64Codec;
import com.wolonghy.secure.api.compress.GzipCompressor;
import com.wolonghy.secure.api.crypto.AesGcmCipher;
import com.wolonghy.secure.api.exception.SecureApiException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the wolonghy-secure-api library.
 *
 * @author Zhang Ze
 * @since 1.0.0
 */
class SecureApiTest {

    private static final String TEST_KEY = "12345678901234567890123456789012";

    // ==================== SecureApi Integration Test ====================

    @Test
    void encryptAndDecrypt_shouldReturnOriginalPlaintext() {
        String plaintext = "{\"userId\":\"123\",\"data\":\"Hello World\"}";
        String encrypted = SecureApi.encrypt(plaintext, TEST_KEY);
        assertNotNull(encrypted);
        assertNotEquals(plaintext, encrypted);

        String decrypted = SecureApi.decrypt(encrypted, TEST_KEY);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void encryptAndDecrypt_withChineseCharacters() {
        String plaintext = "{\"message\":\"你好世界，测试中文加解密\"}";
        String encrypted = SecureApi.encrypt(plaintext, TEST_KEY);
        String decrypted = SecureApi.decrypt(encrypted, TEST_KEY);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void encrypt_shouldReturnNull_whenPlaintextIsNull() {
        assertNull(SecureApi.encrypt(null, TEST_KEY));
    }

    @Test
    void decrypt_shouldReturnNull_whenCiphertextIsNull() {
        assertNull(SecureApi.decrypt(null, TEST_KEY));
    }

    @Test
    void decrypt_shouldThrowException_whenCiphertextIsEmpty() {
        assertThrows(SecureApiException.class, () -> SecureApi.decrypt("", TEST_KEY));
    }

    @Test
    void decrypt_withCustomMaxDecompressedSize_shouldRoundTrip() {
        String plaintext = "{\"data\":\"test\"}";
        String encrypted = SecureApi.encrypt(plaintext, TEST_KEY);
        String decrypted = SecureApi.decrypt(encrypted, TEST_KEY, 10 * 1024 * 1024);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void decrypt_shouldThrowException_whenDecompressedDataExceedsMaxSize() {
        String plaintext = "this is some test data that will exceed the tiny limit";
        String encrypted = SecureApi.encrypt(plaintext, TEST_KEY);
        assertThrows(SecureApiException.class, () -> SecureApi.decrypt(encrypted, TEST_KEY, 5));
    }

    @Test
    void encrypt_shouldThrowException_whenKeyIsNull() {
        assertThrows(IllegalArgumentException.class, () -> SecureApi.encrypt("test", null));
    }

    @Test
    void encrypt_shouldThrowException_whenKeyLengthIsInvalid() {
        assertThrows(IllegalArgumentException.class, () -> SecureApi.encrypt("test", "shortkey"));
    }

    @Test
    void decrypt_shouldThrowException_whenDataIsTampered() {
        String encrypted = SecureApi.encrypt("test data", TEST_KEY);
        String tampered = encrypted.substring(0, encrypted.length() - 5) + "XXXXX";
        assertThrows(SecureApiException.class, () -> SecureApi.decrypt(tampered, TEST_KEY));
    }

    @Test
    void encryptBytesAndDecryptBytes_shouldRoundTrip() {
        byte[] data = "raw byte array test".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = SecureApi.encryptBytes(data, TEST_KEY);
        byte[] decrypted = SecureApi.decryptBytes(encrypted, TEST_KEY);
        assertArrayEquals(data, decrypted);
    }

    @Test
    void encrypt_shouldProduceDifferentCiphertexts_eachTime() {
        String plaintext = "same plaintext";
        String encrypted1 = SecureApi.encrypt(plaintext, TEST_KEY);
        String encrypted2 = SecureApi.encrypt(plaintext, TEST_KEY);
        assertNotEquals(encrypted1, encrypted2, "Each encryption should produce different output due to random IV");
    }

    @Test
    void encryptWithoutCompression_andDecrypt_shouldRoundTrip() {
        String plaintext = "{\"userId\":\"123\",\"data\":\"Hello World\"}";
        String encrypted = SecureApi.encryptWithoutCompression(plaintext, TEST_KEY);
        assertNotNull(encrypted);
        String decrypted = SecureApi.decryptWithoutCompression(encrypted, TEST_KEY);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void encryptWithoutCompression_shouldReturnNull_whenPlaintextIsNull() {
        assertNull(SecureApi.encryptWithoutCompression(null, TEST_KEY));
    }

    @Test
    void decryptWithoutCompression_shouldReturnNull_whenCiphertextIsNull() {
        assertNull(SecureApi.decryptWithoutCompression(null, TEST_KEY));
    }

    // ==================== AesGcmCipher Tests ====================

    @Test
    void aesGcmCipher_generateKey_shouldReturn32Bytes() {
        byte[] key = AesGcmCipher.generateKey();
        assertEquals(32, key.length);
    }

    @Test
    void aesGcmCipher_encryptDecrypt_withGeneratedKey() {
        byte[] key = AesGcmCipher.generateKey();
        byte[] plaintext = "AES-GCM direct test".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = AesGcmCipher.encrypt(key, plaintext);
        byte[] decrypted = AesGcmCipher.decrypt(key, encrypted);
        assertArrayEquals(plaintext, decrypted);
    }

    // ==================== Base64Codec Tests ====================

    @Test
    void base64Codec_encodeAndDecode() {
        byte[] data = "Hello Base64".getBytes(StandardCharsets.UTF_8);
        String encoded = Base64Codec.encode(data);
        byte[] decoded = Base64Codec.decode(encoded);
        assertArrayEquals(data, decoded);
    }

    @Test
    void base64Codec_urlSafe_encodeAndDecode() {
        byte[] data = {(byte) 0xFF, (byte) 0xFE, (byte) 0xFD};
        String encoded = Base64Codec.encodeUrlSafe(data);
        assertFalse(encoded.contains("+"));
        assertFalse(encoded.contains("/"));
        byte[] decoded = Base64Codec.decodeUrlSafe(encoded);
        assertArrayEquals(data, decoded);
    }

    // ==================== GzipCompressor Tests ====================

    @Test
    void gzipCompressor_compressAndDecompress_shouldRoundTrip() {
        byte[] data = "Hello Gzip compression test".getBytes(StandardCharsets.UTF_8);
        byte[] compressed = GzipCompressor.compress(data);
        assertNotNull(compressed);
        assertTrue(compressed.length > 0);
        byte[] decompressed = GzipCompressor.decompress(compressed);
        assertArrayEquals(data, decompressed);
    }

    @Test
    void gzipCompressor_compress_shouldReduceSize_whenDataIsLargeAndRepetitive() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            sb.append("Hello Gzip compression test with some repeated content content content. ");
        }
        byte[] data = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] compressed = GzipCompressor.compress(data);
        assertTrue(compressed.length < data.length, "Compressed data should be smaller for large repetitive input");
        byte[] decompressed = GzipCompressor.decompress(compressed);
        assertArrayEquals(data, decompressed);
    }

    @Test
    void gzipCompressor_emptyData() {
        byte[] compressed = GzipCompressor.compress(new byte[0]);
        assertEquals(0, compressed.length);
        byte[] decompressed = GzipCompressor.decompress(compressed);
        assertEquals(0, decompressed.length);
    }

    @Test
    void gzipCompressor_decompress_withCustomMaxSize() {
        byte[] data = "Hello Gzip".getBytes(StandardCharsets.UTF_8);
        byte[] compressed = GzipCompressor.compress(data);
        byte[] decompressed = GzipCompressor.decompress(compressed, 1024);
        assertArrayEquals(data, decompressed);
    }

    @Test
    void gzipCompressor_decompress_shouldThrowException_whenExceedsMaxSize() {
        byte[] data = "Hello Gzip compression test with some repeated content content content".getBytes(StandardCharsets.UTF_8);
        byte[] compressed = GzipCompressor.compress(data);
        assertThrows(SecureApiException.class, () -> GzipCompressor.decompress(compressed, 5));
    }

    @Test
    void gzipCompressor_decompress_shouldThrowException_whenMaxSizeIsNotPositive() {
        byte[] data = "test".getBytes(StandardCharsets.UTF_8);
        byte[] compressed = GzipCompressor.compress(data);
        assertThrows(IllegalArgumentException.class, () -> GzipCompressor.decompress(compressed, 0));
        assertThrows(IllegalArgumentException.class, () -> GzipCompressor.decompress(compressed, -1));
    }
}
