package com.schmitt.encryption.poc.encryptor;

import javax.crypto.Cipher;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Optional;

public interface Encryptor {
    Optional<String> encrypt(String plaintextContent, Cipher encryptionCipher);

    Optional<String> encrypt(String plaintextContent, Cipher encryptionCipher, AlgorithmParameterSpec algorithmParameterSpec);
}
