package com.schmitt.encryption.poc.cipher;

import javax.crypto.Cipher;
import java.util.Optional;

/**
 * Ciphers need to be initialized in order to be used. Each initialization could be conducted with
 * unique components (cipher value, security provider, padding algo...) and for that reason
 * we should not re-use ciphers amongst invocations.
 * We use a Factory pattern in order to remove repeated use of a single cipher.
 */
public interface CipherFactory {
    Optional<Cipher> getCipher();
}
