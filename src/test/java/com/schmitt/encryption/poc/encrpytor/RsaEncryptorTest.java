package com.schmitt.encryption.poc.encrpytor;

import static org.assertj.core.api.Assertions.assertThat;

import com.schmitt.encryption.poc.encryptor.RsaEncryptor;
import java.util.Optional;
import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class RsaEncryptorTest {

    @Autowired
    private RsaEncryptor rsaEncryptor;

    @Test
    public void itReturnsTrueWhenEncryptedTextIsDifferentFromOriginalText() throws Exception {
        String originalString = "This is a test string";
        Optional<String> encryptedOptional =
                rsaEncryptor.encrypt(originalString, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding"));

        boolean isEncrypted = encryptedOptional
                .map(encrypted -> !encrypted.equals(originalString))
                .orElse(false);

        assertThat(isEncrypted).isTrue();
    }
}
