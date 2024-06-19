package com.schmitt.encryption.poc.service;

import com.schmitt.encryption.poc.cipher.CipherFactory;
import com.schmitt.encryption.poc.decryptor.Decryptor;
import com.schmitt.encryption.poc.encryptor.Encryptor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Optional;
import java.util.function.BiFunction;

@Slf4j
public abstract class AbstractEncryptionService implements EncryptionService {
    protected abstract CipherFactory getCipherFactory();
    protected abstract Encryptor getEncryptor();
    protected abstract Decryptor getDecryptor();
    protected abstract Optional<AlgorithmParameterSpec> getAlgorithmParameterSpec();

    // Based on the availability of the AlgorithmParamterSpec calls the appropriate encryption method
    private final BiFunction<String, Cipher, Optional<String>> getEncryptionFunction =
            (plainTextContent, encryptionCipher) -> getAlgorithmParameterSpec()
                    .map(algorithmParameterSpec -> getEncryptor().encrypt(plainTextContent, encryptionCipher, algorithmParameterSpec))
                    .orElseGet(() -> getEncryptor().encrypt(plainTextContent, encryptionCipher));

    // Based on the availability of the AlgorithmParamterSpec calls the appropriate decryption method
    private final BiFunction<String, Cipher, Optional<String>> getDecryptionFunction =
            (encryptedContent, decryptionCipher) -> getAlgorithmParameterSpec()
                    .map(algorithmParameterSpec -> getDecryptor().decrypt(encryptedContent, decryptionCipher, algorithmParameterSpec))
                    .orElseGet(() -> getDecryptor().decrypt(encryptedContent, decryptionCipher));

    @Override
    public Optional<String> encrypt(String plainTextFileContent) {
        return getCipherFactory().getCipher()
                .flatMap(encryptionCipher -> getEncryptionFunction.apply(plainTextFileContent, encryptionCipher));
    }

    @Override
    public boolean encrypt(String plainTextFileContent, File persistenceLocation) {
        return getCipherFactory().getCipher()
                .flatMap(encryptionCipher -> getEncryptionFunction.apply(plainTextFileContent, encryptionCipher))
                .map(encryptedResult -> writeContentToFile(persistenceLocation,
                        encryptedResult.getBytes(), "Error writing encrypted content to file"))
                .orElseGet(() -> {
                    log.warn("Encrypted content persistence failure - no content returned from encryptor, nothing will be persisted");

                    return false;
                });
    }

    @Override
    public Optional<String> decrypt(String encryptedFileContent) {
        return getCipherFactory().getCipher()
                .flatMap(decryptionCipher -> getDecryptionFunction.apply(encryptedFileContent, decryptionCipher));
    }

    @Override
    public boolean decrypt(String encryptedFileContent, File persistenceLocation) {
        return getCipherFactory().getCipher()
                .flatMap(decryptionCipher -> getDecryptionFunction.apply( encryptedFileContent, decryptionCipher))
                .map(decryptedResult -> writeContentToFile(persistenceLocation,
                        decryptedResult.getBytes(), "Error writing decrypted content to file"))
                .orElseGet(() -> {
                    log.warn("Decrypted content persistence failure - no content returned from decryptor, nothing will be persisted");

                    return false;
                });
    }

    private boolean writeContentToFile(File persistenceLocation, byte[] contentToWrite, String errorMessage) {
        try(FileOutputStream fos = new FileOutputStream(persistenceLocation, false)) {
            fos.write(contentToWrite);

            return true;
        } catch (IOException e) {
            log.error("{}: {}", errorMessage, e.getMessage());
        }
        return false;
    }
}
