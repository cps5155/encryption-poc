package com.schmitt.encryption.poc.config;

import com.schmitt.encryption.poc.encryptor.RsaEncryptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

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
        return new RsaEncryptor(keyPair.getPublic());
    }
}
