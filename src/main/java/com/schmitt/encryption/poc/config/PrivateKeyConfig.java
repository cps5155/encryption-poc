package com.schmitt.encryption.poc.config;

import com.schmitt.encryption.poc.cipher.CipherFactory;
import com.schmitt.encryption.poc.decoder.Base64Decoder;
import com.schmitt.encryption.poc.decryptor.RsaDecryptor;
import com.schmitt.encryption.poc.encryptor.RsaEncryptor;
import com.schmitt.encryption.poc.service.RsaEncryptionService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.lang.Nullable;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

@Configuration
public class PrivateKeyConfig {

    @Value("${app.decoded.keystore.path}")
    private String decodedKeystorePath;

    @Value("${app.keystore.password}")
    private String keystorePassword;

    @Value("${app.keystore.alias}")
    private String keystoreAlias;

    @Autowired
    private Base64Decoder base64Decoder;

    @Bean
    public KeyPair keyPair() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {

        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try {
            base64Decoder.decodeFile();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        try (InputStream in = Files.newInputStream(Paths.get(decodedKeystorePath))) {
            keyStore.load(in, keystorePassword.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Key privateKey = keyStore.getKey(keystoreAlias, keystorePassword.toCharArray());
        Certificate cert = keyStore.getCertificate(keystoreAlias);
        PublicKey publicKey = cert.getPublicKey();

        return new KeyPair(publicKey, (PrivateKey) privateKey);
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
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }

    // This is an example - an Encryption Service would be configured based on a specific provider's needs
    // i.e. maybe Provider A uses AES cipher w/ no padding but Provider B uses OAEP w/ Sha-256 and MGF1 w/ Sha-256
    // padding
    @Bean
    public RsaEncryptionService rsaEncryptionService(
            RsaEncryptor rsaEncryptor,
            RsaDecryptor rsaDecryptor,
            @Qualifier("oaepWithSHA256AndMGF1PaddingCipherFactory") CipherFactory cipherFactory,
            @Nullable AlgorithmParameterSpec rsaParamSpec) {
        return new RsaEncryptionService(rsaEncryptor, rsaDecryptor, cipherFactory, rsaParamSpec);
    }
}
