package com.marketplace.authentication.exception.exceptions;

import org.springframework.security.core.AuthenticationException;

public class InvalidConfirmationCodeException extends AuthenticationException {

    public InvalidConfirmationCodeException(String message) {
        super(message);
    }

    public InvalidConfirmationCodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
