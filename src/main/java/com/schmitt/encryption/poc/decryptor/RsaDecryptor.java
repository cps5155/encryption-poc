package com.schmitt.encryption.poc.decryptor;

import com.schmitt.encryption.poc.exceptions.IncorrectPrivateKeyException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
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
public class RsaDecryptor implements Decryptor {
    private final PrivateKey privateKey;
    private final boolean decodeEncryptedContent;

    @Override
    public Optional<String> decrypt(String encryptedContent, Cipher decryptionCipher) {
        try {
            decryptionCipher.init(Cipher.DECRYPT_MODE, privateKey);

            return decryptUsingInitializedCipher(encryptedContent, decryptionCipher);
        } catch (InvalidKeyException e) {
            log.error("Caught exception attempting to initialize decryption cipher: {}", e.getMessage());
        }

        return Optional.empty();
    }

    @Override
    public Optional<String> decrypt(
            String encryptedContent, Cipher decryptionCipher, AlgorithmParameterSpec algorithmParameterSpec) {
        try {
            decryptionCipher.init(Cipher.DECRYPT_MODE, privateKey, algorithmParameterSpec);

            return decryptUsingInitializedCipher(encryptedContent, decryptionCipher);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            log.error(
                    "Caught exception attempting to initialize decryption cipher with Algorithm ParameterSpec: {}",
                    e.getMessage());
        }

        return Optional.empty();
    }

    private Optional<String> decryptUsingInitializedCipher(String encryptedContent, Cipher initializedCipher) {
        String decryptedContent = null;

        try {
            final byte[] decodedContent = decodeEncryptedContent
                    ? Base64.getDecoder().decode(encryptedContent.getBytes(StandardCharsets.UTF_8))
                    : encryptedContent.getBytes(StandardCharsets.UTF_8);

            final byte[] encryptedContentBytes = initializedCipher.doFinal(decodedContent);

            decryptedContent = new String(encryptedContentBytes, StandardCharsets.UTF_8);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            log.error("Caught exception attempting to decrypt: {}", e.getMessage());
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IncorrectPrivateKeyException("Incorrect private key used to decrypt data.");
        }

        return Optional.ofNullable(decryptedContent);
    }
}
