package com.schmitt.encryption.poc.config;

import com.schmitt.encryption.poc.decryptor.RsaDecryptor;
import com.schmitt.encryption.poc.encryptor.RsaEncryptor;
import com.schmitt.encryption.poc.service.RsaEncryptionService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.lang.Nullable;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

@Configuration
public class PrivateKeyConfig {

    @Bean
    public KeyPair keyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(4096);
        return keyGen.generateKeyPair();
    }

    @Bean
    public RsaEncryptor rsaEncryptor(KeyPair keyPair) {
        return new RsaEncryptor(keyPair.getPublic(), true);
    }

    @Bean
    public RsaDecryptor rsaDecryptor(KeyPair keyPair) {
        return new RsaDecryptor(keyPair.getPrivate(), true);
    }

    @Bean
    @Scope("prototype")
    public Cipher rsaCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        return Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
    }

    @Bean
    public AlgorithmParameterSpec rsaParamSpec() {
        return new OAEPParameterSpec("SHA-256", "MGF1",
                MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }

    @Bean
    public RsaEncryptionService rsaEncryptionService(RsaEncryptor rsaEncryptor, RsaDecryptor rsaDecryptor,
                                                     Cipher rsaCipher,
                                                     @Nullable AlgorithmParameterSpec rsaParamSpec) {
        return new RsaEncryptionService(rsaEncryptor, rsaDecryptor, rsaCipher)
                .setAlgorithmParameterSpec(rsaParamSpec);
    }
}
