package com.schmitt.encryption.poc.encryptor;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class RsaEncryptor implements Encryptor {
    private final PublicKey publicKey;
    private final boolean encodeEncryptedContent;

    @Override
    public Optional<String> encrypt(String plaintextContent, Cipher encryptionCipher) {
        try {
            encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return encryptUsingInitializedCipher(plaintextContent, encryptionCipher);
        } catch (InvalidKeyException e) {
            log.error("Caught exception attempting to initialize encryption cipher: {}", e.getMessage());
        }

        return Optional.empty();
    }

    @Override
    public Optional<String> encrypt(
            String plaintextContent, Cipher encryptionCipher, AlgorithmParameterSpec algorithmParameterSpec) {
        try {
            encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey, algorithmParameterSpec);

            return encryptUsingInitializedCipher(plaintextContent, encryptionCipher);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            log.error(
                    "Caught exception attempting to initialize encryption cipher with Algorithm ParameterSpec: {}",
                    e.getMessage());
        }

        return Optional.empty();
    }

    private Optional<String> encryptUsingInitializedCipher(String plaintextContent, Cipher initializedCipher) {
        String encryptedContent = null;

        try {
            final byte[] encryptedContentBytes =
                    initializedCipher.doFinal(plaintextContent.getBytes(StandardCharsets.UTF_8));

            encryptedContent = encodeEncryptedContent
                    ? Base64.getEncoder().encodeToString(encryptedContentBytes)
                    : new String(encryptedContentBytes, StandardCharsets.UTF_8);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            log.error("Caught exception attempting to encrypt: {}", e.getMessage());
        }

        return Optional.ofNullable(encryptedContent);
    }
}
