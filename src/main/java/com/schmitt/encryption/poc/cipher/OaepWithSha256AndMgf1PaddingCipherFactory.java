package com.schmitt.encryption.poc.cipher;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Optional;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@Slf4j
public class OaepWithSha256AndMgf1PaddingCipherFactory implements CipherFactory {

    public OaepWithSha256AndMgf1PaddingCipherFactory(BouncyCastleProvider bcProvider) {
        // do nothing
        // although we don't explicitly do anything with the BouncyCastleProvider we need it in order to use this cipher
        // so require it to be available so the factory can assert it can be used to create new ciphers
    }

    @Override
    public Optional<Cipher> getCipher() {
        Cipher cipher = null;

        try {
            cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            log.error("Failed to instantiate new OAEPWithSHA256AndMGF1Padding Cipher: {}", e.getMessage());
        }

        return Optional.ofNullable(cipher);
    }
}
