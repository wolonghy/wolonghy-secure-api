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
package com.wolonghy.secure.api.compress;

import com.wolonghy.secure.api.exception.SecureApiException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Gzip compression and decompression utilities.
 *
 * @author Zhang Ze
 * @since 1.0.0
 */
public final class GzipCompressor {

    private static final int BUFFER_SIZE = 4096;
    private static final int INITIAL_CAPACITY = 2048;

    /**
     * Default maximum decompressed data size: 50 MB.
     *
     * <p>Used by {@link #decompress(byte[])} to guard against decompression bombs.
     * To use a custom limit, call {@link #decompress(byte[], int)} instead.</p>
     */
    public static final int DEFAULT_MAX_DECOMPRESSED_SIZE = 50 * 1024 * 1024;

    private GzipCompressor() {
    }

    /**
     * Compresses data using Gzip.
     *
     * @param data the data to compress
     * @return the compressed bytes
     * @throws SecureApiException if compression fails
     * @throws IllegalArgumentException if data is null
     */
    public static byte[] compress(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data must not be null");
        }
        if (data.length == 0) {
            return new byte[0];
        }
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(INITIAL_CAPACITY);
             GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(data);
            gzip.finish();
            return baos.toByteArray();
        } catch (Exception e) {
            throw new SecureApiException("Gzip compression failed", e);
        }
    }

    /**
     * Decompresses Gzip-compressed data using the default maximum size limit
     * ({@value #DEFAULT_MAX_DECOMPRESSED_SIZE} bytes).
     *
     * @param compressedData the Gzip-compressed bytes
     * @return the decompressed bytes
     * @throws SecureApiException if decompression fails or the decompressed data exceeds the size limit
     * @throws IllegalArgumentException if data is null
     */
    public static byte[] decompress(byte[] compressedData) {
        return decompress(compressedData, DEFAULT_MAX_DECOMPRESSED_SIZE);
    }

    /**
     * Decompresses Gzip-compressed data with a custom maximum size limit.
     *
     * <p>The size limit guards against decompression bombs (a small compressed
     * payload that decompresses to an extremely large size).</p>
     *
     * @param compressedData      the Gzip-compressed bytes
     * @param maxDecompressedSize the maximum allowed decompressed size in bytes, must be positive
     * @return the decompressed bytes
     * @throws SecureApiException if decompression fails or the decompressed data exceeds the size limit
     * @throws IllegalArgumentException if data is null or maxDecompressedSize is not positive
     */
    public static byte[] decompress(byte[] compressedData, int maxDecompressedSize) {
        if (compressedData == null) {
            throw new IllegalArgumentException("Compressed data must not be null");
        }
        if (maxDecompressedSize <= 0) {
            throw new IllegalArgumentException("maxDecompressedSize must be positive, but was " + maxDecompressedSize);
        }
        if (compressedData.length == 0) {
            return new byte[0];
        }
        try (ByteArrayInputStream bais = new ByteArrayInputStream(compressedData);
             GZIPInputStream gzip = new GZIPInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream(INITIAL_CAPACITY)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int len;
            while ((len = gzip.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
                if (baos.size() > maxDecompressedSize) {
                    throw new SecureApiException(
                            "Decompressed data exceeds maximum allowed size of " + maxDecompressedSize + " bytes");
                }
            }
            return baos.toByteArray();
        } catch (SecureApiException e) {
            throw e;
        } catch (Exception e) {
            throw new SecureApiException("Gzip decompression failed", e);
        }
    }
}
