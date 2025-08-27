package com.marketplace.authentication.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.marketplace.authentication.domain.dto.request.ConfirmationRegistrarionCodesDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserCreateDto;
import com.marketplace.authentication.domain.dto.response.RegistrationSessionId;
import com.marketplace.authentication.security.Tokens;
import com.marketplace.authentication.services.CustomerUserAuthenticationService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth/customer-users")
public class CustomerUserAuthenticationController {

    private final CustomerUserAuthenticationService customerUserAuthenticationService;

    @PostMapping("/initiate-registration")
    public ResponseEntity<?> initiateRegistration(@Valid @RequestBody CustomerUserCreateDto dto, 
                            BindingResult bindingResult) throws BindException {
        if (bindingResult.hasErrors()) {
            if (bindingResult instanceof BindException error) {
                throw error;
            } else {
                throw new BindException(bindingResult);
            }
        }

        UUID sessionId = customerUserAuthenticationService.initiateRegistration(dto);
        
        return ResponseEntity.status(HttpStatus.OK).body(new RegistrationSessionId(sessionId.toString()));
    }

    @PostMapping("/confirmation-registration/{sessionId}")
    public ResponseEntity<?> confirmationRegistration(@PathVariable String sessionId, @Valid @RequestBody ConfirmationRegistrarionCodesDto dto, 
                            BindingResult bindingResult) throws BindException {
        if (bindingResult.hasErrors()) {
            if (bindingResult instanceof BindException error) {
                throw error;
            } else {
                throw new BindException(bindingResult);
            }
        }

        Tokens tokens = customerUserAuthenticationService.confirmationRegistration(sessionId, dto);
        
        return ResponseEntity.status(HttpStatus.CREATED).body(tokens);
    }

    @PostMapping("/resend-confirmation-registration/{sessionId}")
    public ResponseEntity<?> resendConfirmationRegistrationCodes(@PathVariable String sessionId) {
        customerUserAuthenticationService.resendConfirmationRegistrationCodes(sessionId);
        return ResponseEntity.noContent().build();
    }
}
