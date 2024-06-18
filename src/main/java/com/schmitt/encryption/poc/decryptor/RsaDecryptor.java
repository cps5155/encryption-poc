package com.schmitt.encryption.poc.decryptor;

import com.schmitt.encryption.poc.common.RsaCipher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class RsaDecryptor extends RsaCipher implements Decryptor {
    private final PrivateKey privateKey;
    private final boolean decodeEncryptedContent;

    @Override
    public Optional<String> decrypt(String encryptedContent) {
        return getCipher().flatMap(decryptionCipher -> decrypt(encryptedContent, decryptionCipher));
    }

    protected Optional<String> decrypt(String encryptedContent, Cipher decryptionCipher) {
        String decryptedContent = null;

        try {
            decryptionCipher.init(Cipher.DECRYPT_MODE, privateKey, getOaepParameterSpec());

            final byte[] decodedContent = decodeEncryptedContent ? Base64.getDecoder().decode(encryptedContent.getBytes(StandardCharsets.UTF_8))
                    : encryptedContent.getBytes(StandardCharsets.UTF_8);

            final byte[] encryptedContentBytes = decryptionCipher.doFinal(decodedContent);

            decryptedContent = new String(encryptedContentBytes, StandardCharsets.UTF_8);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error("Caught exception attempting to decrypt: {}", e.getMessage());
        }

        return Optional.ofNullable(decryptedContent);
    }
}
