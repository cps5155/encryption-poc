package com.schmitt.encryption.poc.exceptions;

public class IncorrectPrivateKeyException extends RuntimeException {
    public IncorrectPrivateKeyException(String message) {
        super(message);
    }
}
