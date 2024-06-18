package com.schmitt.encryption.poc.service;

import com.schmitt.encryption.poc.decryptor.Decryptor;
import com.schmitt.encryption.poc.encryptor.Encryptor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Optional;

@Slf4j
public abstract class AbstractEncryptionService implements EncryptionService {
    protected abstract Cipher getCipher();
    protected abstract Encryptor getEncryptor();
    protected abstract Decryptor getDecryptor();

    @Override
    public Optional<String> encrypt(String plainTextFileContent) {
        return getEncryptor().encrypt(plainTextFileContent, getCipher());
    }

    @Override
    public boolean encrypt(String plainTextFileContent, File persistenceLocation) {
        return getEncryptor().encrypt(plainTextFileContent, getCipher())
                .map(encryptedResult -> writeContentToFile(persistenceLocation,
                        encryptedResult.getBytes(), "Error writing encrypted content to file"))
                .orElseGet(() -> {
                    log.warn("Encrypted content persistence failure - no content returned from encryptor, nothing will be persisted");

                    return false;
                });
    }

    @Override
    public Optional<String> decrypt(String encryptedFileContent) {
        return getDecryptor().decrypt(encryptedFileContent, getCipher());
    }

    @Override
    public boolean decrypt(String encryptedFileContent, File persistenceLocation) {
        return getDecryptor().decrypt(encryptedFileContent, getCipher())
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
