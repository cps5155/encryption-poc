package com.schmitt.encryption.poc.decryptor;

import java.util.Optional;

public interface Decryptor {
    Optional<String> decrypt(String encryptedContent);
}
