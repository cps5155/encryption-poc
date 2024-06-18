package com.schmitt.encryption.poc.service;

import java.io.File;
import java.util.Optional;

public interface EncryptionService {

    Optional<String> encrypt(String plainTextFileContent);

    boolean encrypt(String plainTextFileContent, File persistenceLocation);

    Optional<String> decrypt(String encryptedFileContent);

    boolean decrypt(String encryptedFileContent, File persistenceLocation);
}
