package com.schmitt.encryption.poc.encrpytor;

import static org.assertj.core.api.Assertions.assertThat;

import com.schmitt.encryption.poc.cipher.OaepWithSha256AndMgf1PaddingCipherFactory;
import com.schmitt.encryption.poc.encryptor.RsaEncryptor;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Optional;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RsaEncryptorTest {

    private RsaEncryptor rsaEncryptor;
    private OaepWithSha256AndMgf1PaddingCipherFactory cipherFactory;
    private Cipher cipher;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        rsaEncryptor = new RsaEncryptor(keyPair.getPublic(), true);
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
        cipherFactory = new OaepWithSha256AndMgf1PaddingCipherFactory(bouncyCastleProvider);
        cipher = cipherFactory.getCipher().orElseThrow(() -> new RuntimeException("Failed to get cipher"));
    }

    @Test
    void itReturnsTrueWhenEncryptedTextIsDifferentFromOriginalText() {
        String originalString = "This is a test string";

        Optional<String> encryptedOptional = rsaEncryptor.encrypt(originalString, cipher);

        assertThat(encryptedOptional)
                .hasValueSatisfying(unpackedActual -> assertThat(unpackedActual).isNotEqualTo(originalString));
    }

    @Test
    void itCanEncryptContentWithPublicKey() throws Exception {
        String expectedEncryptedText = new String(Files.readAllBytes(Paths.get("src/test/resources/encrypted.txt")));

        Optional<String> encryptedOptional = rsaEncryptor.encrypt("This is a test string", cipher);

        /*
        the encryptor uses some elements of randomness to encrypt the text, so we can't compare the encrypted text directly and can instead
        verify that our text has been encrypted to a string of the expected length
        */
        assertThat(encryptedOptional).hasValueSatisfying(unpackedActual -> assertThat(unpackedActual)
                .hasSize(expectedEncryptedText.length()));
    }
}
