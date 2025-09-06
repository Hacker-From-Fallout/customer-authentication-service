package com.marketplace.authentication.validation.validators;

import java.util.regex.Pattern;

import com.marketplace.authentication.validation.annotations.NotEmail;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class NotEmailValidator implements ConstraintValidator<NotEmail, String> {

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$");

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) return true;
        return !EMAIL_PATTERN.matcher(value).matches();
    }
}