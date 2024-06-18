package com.schmitt.encryption.poc.encryptor;

import com.schmitt.encryption.poc.common.RsaCipher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class RsaEncryptor extends RsaCipher implements Encryptor {
    private final PublicKey publicKey;
    private final boolean encodeEncryptedContent;

    @Override
    public Optional<String> encrypt(String plaintextContent)  {
        return getCipher().flatMap(encryptionCipher -> encrypt(plaintextContent, encryptionCipher));
    }

    public Optional<String> encrypt(String plaintextContent, Cipher encryptionCipher) {
        String encryptedContent = null;

        try {
            encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey, getOaepParameterSpec());

            final byte [] encryptedContentBytes = encryptionCipher.doFinal(plaintextContent.getBytes(StandardCharsets.UTF_8));

            encryptedContent = encodeEncryptedContent ? Base64.getEncoder().encodeToString(encryptedContentBytes)
                    : new String(encryptedContentBytes, StandardCharsets.UTF_8);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            log.error("Caught exception attempting to encrypt: {}", e.getMessage());
        }

        return Optional.ofNullable(encryptedContent);
    }
}
