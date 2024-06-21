package com.schmitt.encryption.poc.decryptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

import com.schmitt.encryption.poc.cipher.OaepWithSha256AndMgf1PaddingCipherFactory;
import com.schmitt.encryption.poc.encryptor.RsaEncryptor;
import com.schmitt.encryption.poc.exceptions.IncorrectPrivateKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Optional;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RsaDecryptorTest {

    private RsaEncryptor rsaEncryptor;
    private RsaDecryptor rsaDecryptor;
    private OaepWithSha256AndMgf1PaddingCipherFactory cipherFactory;
    private Cipher cipher;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        rsaEncryptor = new RsaEncryptor(keyPair.getPublic(), true);
        rsaDecryptor = new RsaDecryptor(keyPair.getPrivate(), true);
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        cipherFactory = new OaepWithSha256AndMgf1PaddingCipherFactory(bouncyCastleProvider);
        cipher = cipherFactory.getCipher().orElseThrow(() -> new RuntimeException("Failed to get cipher"));
    }

    @Test
    void itReturnsTrueWhenDecryptedStringMatchesOriginalString() {
        String originalString = "This is a test string";
        Optional<String> encryptedOptional = rsaEncryptor.encrypt(originalString, cipher);

        String encrypted = encryptedOptional.orElseThrow(() -> new RuntimeException("Failed to encrypt"));

        Optional<String> decryptedOptional = rsaDecryptor.decrypt(encrypted, cipher);

        assertThat(decryptedOptional).hasValue(originalString);
    }

    @Test
    void itThrowsExceptionWhenDecryptedWithDifferentPrivateKey() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RsaDecryptor differentPrivateKey = new RsaDecryptor(keyPair.getPrivate(), true);

        String originalString = "This is a test string";
        Optional<String> encryptedOptional = rsaEncryptor.encrypt(originalString, cipher);

        String encrypted = encryptedOptional.orElseThrow(() -> new RuntimeException("Failed to encrypt"));

        Throwable throwable = catchThrowable(() -> differentPrivateKey.decrypt(encrypted, cipher));

        assertThat(throwable).isInstanceOf(IncorrectPrivateKeyException.class);
    }

    @Test
    void itCanNotDecryptWithIncorrectCipher() throws Exception {
        String originalString = "This is a test string";

        Optional<String> encryptedOptional =
                rsaEncryptor.encrypt(originalString, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding"));

        String encrypted = encryptedOptional.orElseThrow(() -> new RuntimeException("Failed to encrypt"));

        Optional<String> decryptedOptional =
                rsaDecryptor.decrypt(encrypted, Cipher.getInstance("RSA/ECB/PKCS1Padding"));

        assertThat(decryptedOptional).isEmpty();
    }
}
