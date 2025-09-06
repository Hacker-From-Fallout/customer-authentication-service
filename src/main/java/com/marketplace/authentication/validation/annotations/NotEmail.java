package com.marketplace.authentication.validation.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.marketplace.authentication.validation.validators.NotEmailValidator;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Target({ ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = NotEmailValidator.class)
public @interface NotEmail {
    String message() default "Username must not be in email format";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
