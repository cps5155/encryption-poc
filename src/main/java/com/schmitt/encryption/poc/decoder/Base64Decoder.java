package com.schmitt.encryption.poc.decoder;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;

public class Base64Decoder {

    @Value("${app.encoded.keystore.path}")
    private String encodedKeystorePath;

    @Value("${app.decoded.keystore.path}")
    private String decodedKeystorePath;

    public void decodeFile() throws Exception {
        String base64 = new String(Files.readAllBytes(Paths.get(encodedKeystorePath)));

        byte[] decoded = Base64.getDecoder().decode(base64);

        Files.write(Paths.get(decodedKeystorePath), decoded);
    }
}
