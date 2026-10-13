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
package com.wolonghy.secure.api.codec;

import com.wolonghy.secure.api.exception.SecureApiException;

import java.util.Base64;

/**
 * Base64 encoding and decoding utilities.
 *
 * <p>Provides both standard Base64 and URL-safe Base64 variants.</p>
 *
 * @author Zhang Ze
 * @since 1.0.0
 */
public final class Base64Codec {

    private Base64Codec() {
    }

    /**
     * Encodes bytes to a standard Base64 string.
     *
     * @param data the data to encode
     * @return the Base64-encoded string
     * @throws IllegalArgumentException if data is null
     */
    public static String encode(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data must not be null");
        }
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Decodes a standard Base64 string to bytes.
     *
     * @param base64 the Base64-encoded string
     * @return the decoded bytes
     * @throws SecureApiException if the string is not valid Base64
     */
    public static byte[] decode(String base64) {
        if (base64 == null) {
            throw new IllegalArgumentException("Base64 string must not be null");
        }
        if (base64.isEmpty()) {
            return new byte[0];
        }
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new SecureApiException("Invalid Base64 input", e);
        }
    }

    /**
     * Encodes bytes to a URL-safe Base64 string (no padding).
     *
     * @param data the data to encode
     * @return the URL-safe Base64-encoded string
     * @throws IllegalArgumentException if data is null
     */
    public static String encodeUrlSafe(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data must not be null");
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Decodes a URL-safe Base64 string to bytes.
     *
     * @param base64Url the URL-safe Base64-encoded string
     * @return the decoded bytes
     * @throws SecureApiException if the string is not valid URL-safe Base64
     */
    public static byte[] decodeUrlSafe(String base64Url) {
        if (base64Url == null) {
            throw new IllegalArgumentException("URL-safe Base64 string must not be null");
        }
        if (base64Url.isEmpty()) {
            return new byte[0];
        }
        try {
            return Base64.getUrlDecoder().decode(base64Url);
        } catch (IllegalArgumentException e) {
            throw new SecureApiException("Invalid URL-safe Base64 input", e);
        }
    }
}
