package com.schmitt.encryption.poc.decryptor;

import com.schmitt.encryption.poc.encryptor.RsaEncryptor;
import com.schmitt.encryption.poc.exceptions.IncorrectPrivateKeyException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

@SpringBootTest
public class RsaDecryptorTest {

    @Autowired
    private RsaEncryptor rsaEncryptor;

    @Autowired
    private RsaDecryptor rsaDecryptor;

    @Test
    void itReturnsTrueWhenDecryptedStringMatchesOriginalString() throws Exception {
        String originalString = "This is a test string";
        Optional<String> encryptedOptional =
                rsaEncryptor.encrypt(originalString, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding"));

        String encrypted = encryptedOptional.orElseThrow(() -> new RuntimeException("Failed to encrypt"));

        Optional<String> decryptedOptional =
                rsaDecryptor.decrypt(encrypted, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding"));

        assertThat(decryptedOptional).hasValue(originalString);
    }

    @Test
    void itThrowsExceptionWhenDecryptedWithDifferentPrivateKey() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RsaDecryptor differentPrivateKey = new RsaDecryptor(keyPair.getPrivate(), true);

        String originalString = "This is a test string";
        Optional<String> encryptedOptional =
                rsaEncryptor.encrypt(originalString, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding"));

        String encrypted = encryptedOptional.orElseThrow(() -> new RuntimeException("Failed to encrypt"));

        Throwable throwable = catchThrowable(() ->
                differentPrivateKey.decrypt(encrypted, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding")));

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
