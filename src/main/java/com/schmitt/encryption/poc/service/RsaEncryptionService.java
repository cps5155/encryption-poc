package com.schmitt.encryption.poc.service;

import com.schmitt.encryption.poc.cipher.CipherFactory;
import com.schmitt.encryption.poc.decryptor.RsaDecryptor;
import com.schmitt.encryption.poc.encryptor.RsaEncryptor;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Optional;

@Getter
@AllArgsConstructor
@Accessors(chain = true)
@RequiredArgsConstructor
public class RsaEncryptionService extends AbstractEncryptionService {
    private final RsaEncryptor encryptor;
    private final RsaDecryptor decryptor;
    private final CipherFactory cipherFactory;
    private AlgorithmParameterSpec algorithmParameterSpec;

    public Optional<AlgorithmParameterSpec> getAlgorithmParameterSpec() {
        return Optional.ofNullable(algorithmParameterSpec);
    }
}
