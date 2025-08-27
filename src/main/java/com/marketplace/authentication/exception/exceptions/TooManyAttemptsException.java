package com.marketplace.authentication.exception.exceptions;

public class TooManyAttemptsException extends RuntimeException{
    public TooManyAttemptsException(String message) {
        super(message);
    }
}
