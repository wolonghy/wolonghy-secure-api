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
package com.wolonghy.secure.api.exception;

/**
 * Runtime exception thrown by wolonghy-secure-api when a cryptographic,
 * compression, or encoding operation fails.
 *
 * <p>This is an unchecked exception to minimize boilerplate in calling code.
 * Catch it only when you need to handle security-related failures explicitly.</p>
 *
 * <pre>{@code
 * try {
 *     String encrypted = SecureApi.encrypt(plaintext, key);
 * } catch (SecureApiException e) {
 *     // handle encryption failure
 * }
 * }</pre>
 *
 * @author Zhang Ze
 * @since 1.0.0
 */
public class SecureApiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public SecureApiException(String message) {
        super(message);
    }

    public SecureApiException(String message, Throwable cause) {
        super(message, cause);
    }
}
