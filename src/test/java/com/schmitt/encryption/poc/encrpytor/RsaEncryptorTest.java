package com.schmitt.encryption.poc.encrpytor;

import com.schmitt.encryption.poc.encryptor.RsaEncryptor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.Cipher;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class RsaEncryptorTest {

    @Autowired
    private RsaEncryptor rsaEncryptor;

    @Value("${app.cipher.padding.schema}")
    private String cipherPaddingSchema;

    @Test
    public void itReturnsTrueWhenEncryptedTextIsDifferentFromOriginalText() throws Exception {
        String originalString = "This is a test string";
        String encrypted = rsaEncryptor
                .encrypt(originalString, Cipher.getInstance(cipherPaddingSchema))
                .get();

        assertThat(encrypted).isNotEqualTo(originalString);
    }
}
