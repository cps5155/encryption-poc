package com.schmitt.encryption.poc.config.cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;

import java.security.Security;


public class BouncyCastleSecurityProviderConfig {
    @Bean
    @Scope("singleton")
    public BouncyCastleProvider registeredBouncyCastleProvider() {
        final BouncyCastleProvider bcProvider = new BouncyCastleProvider();

        // ensure provider is registered with Java security through at least once bean usage
        Security.addProvider(bcProvider);

        return bcProvider;
    }
}
