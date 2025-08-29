package com.marketplace.authentication.exception.exceptions;

public class AuthenticationSessionNotFound extends RuntimeException {

    public AuthenticationSessionNotFound(String message) {
        super(message);
    }
}
