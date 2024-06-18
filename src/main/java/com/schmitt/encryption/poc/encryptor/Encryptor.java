package com.schmitt.encryption.poc.encryptor;

import java.util.Optional;

public interface Encryptor {
    Optional<String> encrypt(String plaintextContent);
}
