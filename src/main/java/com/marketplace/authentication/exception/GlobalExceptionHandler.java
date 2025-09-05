package com.marketplace.authentication.exception;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.BindException;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.marketplace.authentication.exception.exceptions.AlreadyExistsException;
import com.marketplace.authentication.exception.exceptions.AuthenticationSessionNotFound;
import com.marketplace.authentication.exception.exceptions.InvalidConfirmationCodeException;
import com.marketplace.authentication.exception.exceptions.InvalidRefreshTokenException;
import com.marketplace.authentication.exception.exceptions.RegistrationSessionNotFound;
import com.marketplace.authentication.exception.exceptions.TooManyAttemptsException;
import com.marketplace.authentication.exception.exceptions.UserNotFoundException;
import com.marketplace.authentication.exception.exceptions.VerificationRegistrationCodesException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private final MessageSource messageSource;

    @ExceptionHandler(BindException.class)
    public ResponseEntity<ProblemDetail> handleBindException(BindException exception, Locale locale) {
        log.warn("BindException: {}", exception.getMessage());
        
        ProblemDetail problemDetail = ProblemDetail
            .forStatusAndDetail(HttpStatus.BAD_REQUEST,
                this.messageSource.getMessage("errors.400.title", new Object[0],
                    "errors.400.title", locale));
        problemDetail.setProperty("errors",
            exception.getAllErrors().stream()
            .map(ObjectError::getDefaultMessage)
            .toList());

        return ResponseEntity.badRequest()
            .body(problemDetail);
    }

    @ExceptionHandler(RegistrationSessionNotFound.class)
    public ResponseEntity<ProblemDetail> handleRegistrationSessionNotFound(RegistrationSessionNotFound exception,
        Locale locale) {
        log.info("RegistrationSessionNotFound: {}", exception.getMessage());
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST,
                this.messageSource.getMessage(exception.getMessage(), new Object[0],
                    exception.getMessage(), locale)));
    }

    @ExceptionHandler(AuthenticationSessionNotFound.class)
    public ResponseEntity<ProblemDetail> handleAuthenticationSessionNotFound(AuthenticationSessionNotFound exception,
        Locale locale) {
        log.info("AuthenticationSessionNotFound: {}", exception.getMessage());
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST,
                this.messageSource.getMessage(exception.getMessage(), new Object[0],
                    exception.getMessage(), locale)));
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ProblemDetail> handleInvalidRefreshTokenException(InvalidRefreshTokenException exception,
        Locale locale) {
        log.info("InvalidRefreshTokenException: {}", exception.getMessage());
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED,
                this.messageSource.getMessage(exception.getMessage(), new Object[0],
                    exception.getMessage(), locale)));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ProblemDetail> handleBadCredentialsException(BadCredentialsException exception,
        Locale locale) {
        log.info("BadCredentialsException: {}", exception.getMessage());
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED,
                this.messageSource.getMessage(exception.getMessage(), new Object[0],
                    exception.getMessage(), locale)));
    }

    @ExceptionHandler(InvalidConfirmationCodeException.class)
    public ResponseEntity<ProblemDetail> handleInvalidConfirmationCodeException(InvalidConfirmationCodeException exception,
        Locale locale) {
        log.info("InvalidConfirmationCodeException: {}", exception.getMessage());
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED,
                this.messageSource.getMessage(exception.getMessage(), new Object[0],
                    exception.getMessage(), locale)));
    }

    @ExceptionHandler(VerificationRegistrationCodesException.class)
    public ResponseEntity<ProblemDetail> handleVerificationRegistrationCodesException(VerificationRegistrationCodesException exception,
        Locale locale) {
        log.info("VerificationRegistrationCodesException: {}", exception.getMessage());
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST,
                this.messageSource.getMessage(exception.getMessage(), new Object[0],
                    exception.getMessage(), locale)));
    }

    @ExceptionHandler(TooManyAttemptsException.class)
    public ResponseEntity<ProblemDetail> handleTooManyAttemptsException(TooManyAttemptsException exception,
        Locale locale) {
        log.info("TooManyAttemptsException: {}", exception.getMessage());
        
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
            .body(ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS,
                this.messageSource.getMessage(exception.getMessage(), new Object[0],
                    exception.getMessage(), locale)));
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleUserNotFoundException(UserNotFoundException exception,
        Locale locale) {
        log.info("UserNotFoundException: {}", exception.getMessage());
        
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND,
                this.messageSource.getMessage(exception.getMessage(), new Object[0],
                    exception.getMessage(), locale)));
    }

    @ExceptionHandler(AlreadyExistsException.class)
    public ResponseEntity<ProblemDetail> handleAlreadyExistsException(AlreadyExistsException exception,
        Locale locale) {
        log.warn("AlreadyExistsException: {}", exception.getMessage());
        
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT,
                this.messageSource.getMessage(exception.getMessage(), new Object[0],
                    exception.getMessage(), locale)));
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException exception,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {

        log.warn("MethodArgumentNotValidException: {}", exception.getMessage());

        Locale locale = LocaleContextHolder.getLocale();

        List<String> errors = exception.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(fieldError -> {
                    String message = messageSource.getMessage(fieldError, locale);
                    return String.format("%s: %s", fieldError.getField(), message);
                })
                .collect(Collectors.toList());

        String detailMessage = String.join("; ", errors);

        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, 
                detailMessage
        );

        return this.handleExceptionInternal(exception, problemDetail, headers, status, request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleException(Exception exception, Locale locale) {
        log.error("Unexpected error occurred: ", exception);
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR,
                this.messageSource.getMessage("Ошибка на сервере", new Object[0],
                    "Ошибка на сервере", locale)));
    }
}