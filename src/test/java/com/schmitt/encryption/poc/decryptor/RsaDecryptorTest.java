package com.schmitt.encryption.poc.decryptor;

import com.schmitt.encryption.poc.encryptor.RsaEncryptor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
public class RsaDecryptorTest {

    @Autowired
    private RsaEncryptor rsaEncryptor;

    @Autowired
    private RsaDecryptor rsaDecryptor;

    @Test
    public void itReturnsTrueWhenDecryptedStringMatchesOriginalString() throws Exception {
        String originalString = "This is a test string";
        String encrypted = rsaEncryptor
                .encrypt(originalString, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding"))
                .get();
        String decrypted = rsaDecryptor
                .decrypt(encrypted, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding"))
                .get();

        assertThat(decrypted).isEqualTo(originalString);
    }

    @Test
    public void itThrowsExceptionWhenDecryptedWithDifferentPrivateKey() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RsaDecryptor differentPrivateKey = new RsaDecryptor(keyPair.getPrivate(), true);

        String originalString = "This is a test string";
        String encrypted = rsaEncryptor
                .encrypt(originalString, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding"))
                .get();

        // Array index out of bounds exceptions are thrown when trying to decrypt data with the wrong private key
        assertThatThrownBy(() -> differentPrivateKey
                .decrypt(encrypted, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding"))
                .get())
                .isInstanceOf(ArrayIndexOutOfBoundsException.class);
    }

    @Test
    public void itCanNotDecryptWithIncorrectCipher() throws Exception {
        String originalString = "This is a test string";
        String encrypted = rsaEncryptor
                .encrypt(originalString, Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding"))
                .get();
        Optional<String> decryptedOptional = rsaDecryptor
                .decrypt(encrypted, Cipher.getInstance("RSA/ECB/PKCS1Padding"));

        assertThat(decryptedOptional).isEmpty();
    }
}
