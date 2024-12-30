package org.apache.syncope.core.spring;

import org.apache.syncope.core.spring.security.Encryptor;

public class EncryptorFactory {

    private EncryptorFactory() {
        // Prevent instantiation
    }

    public static Encryptor createEncryptor(String secretKey) {
        return Encryptor.getInstance(secretKey);
    }
}