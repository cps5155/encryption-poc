package com.schmitt.encryption.poc.decryptor;

import javax.crypto.Cipher;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Optional;

public interface Decryptor {
    Optional<String> decrypt(String encryptedContent, Cipher decryptionCipher);

    Optional<String> decrypt(String encryptedContent, Cipher decryptionCipher, AlgorithmParameterSpec algorithmParameterSpec);
}
