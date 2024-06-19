package com.schmitt.encryption.poc.config.cipher;

import com.schmitt.encryption.poc.cipher.OaepWithSha256AndMgf1PaddingCipherFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import(BouncyCastleSecurityProviderConfig.class)
public class OaepWithSha256AndMgf1PaddingCipherFactoryConfig {

    @Bean
    public OaepWithSha256AndMgf1PaddingCipherFactory oaepWithSHA256AndMGF1PaddingCipherFactory(BouncyCastleProvider bouncyCastleProvider) {
        return new OaepWithSha256AndMgf1PaddingCipherFactory(bouncyCastleProvider);
    }
}
