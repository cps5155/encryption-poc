package com.schmitt.encryption.poc.common;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Optional;

@Getter
@Slf4j
public abstract class RsaCipher {
    protected OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-256", "MGF1",
                                                                                MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    protected Optional<Cipher> getCipher() {
        Cipher encryptionCipher = null;
        try {
            // get an RSA cipher object and print the provider
            encryptionCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException e) {
            log.error("Caught Exception trying to obtain cipher: {}", e.getMessage());
        }
        return Optional.ofNullable(encryptionCipher);
    }
}
