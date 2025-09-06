package com.marketplace.authentication.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.marketplace.authentication.domain.dto.request.ConfirmationCodeDto;
import com.marketplace.authentication.domain.dto.request.ConfirmationRegistrarionCodesDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserAuthenticationDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserCreateDto;
import com.marketplace.authentication.domain.dto.request.RefreshTokenDto;
import com.marketplace.authentication.domain.dto.response.AccessTokenDto;
import com.marketplace.authentication.domain.dto.response.AuthenticationResponse;
import com.marketplace.authentication.domain.dto.response.RegistrationSessionId;
import com.marketplace.authentication.security.Tokens;
import com.marketplace.authentication.services.AuthenticationService;
import com.marketplace.authentication.services.RegistrationService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final RegistrationService registrationService;

    @PostMapping("/initiate-registration")
    public ResponseEntity<?> initiateRegistration(@Valid @RequestBody CustomerUserCreateDto dto) {
        UUID sessionId = registrationService.initiateRegistration(dto);
        return ResponseEntity.status(HttpStatus.OK).body(new RegistrationSessionId(sessionId.toString()));
    }

    @PostMapping("/confirmation-registration/{sessionId}")
    public ResponseEntity<?> confirmationRegistration(@PathVariable String sessionId, 
        @Valid @RequestBody ConfirmationRegistrarionCodesDto dto) {

        Tokens tokens = registrationService.confirmationRegistration(sessionId, dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(tokens);
    }

    @PostMapping("/resend-confirmation-registration/{sessionId}")
    public ResponseEntity<?> resendConfirmationRegistrationCodes(@PathVariable String sessionId) {
        registrationService.resendConfirmationRegistrationCodes(sessionId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/login")
    public ResponseEntity<?> usernamePasswordAuthenticate(@Valid @RequestBody CustomerUserAuthenticationDto dto) {
        AuthenticationResponse authenticationResponse = 
            authenticationService.usernamePasswordAuthenticate(dto);

        return authenticationResponse.authenticated() 
            ? ResponseEntity.ok().body(authenticationResponse)
            : ResponseEntity.status(HttpStatus.ACCEPTED).body(authenticationResponse);
    }

    @PostMapping("/confirmation-email/{sessionId}")
    public ResponseEntity<?> emailConfirmationCodeAuthenticate(@PathVariable String sessionId, @Valid @RequestBody ConfirmationCodeDto dto) {
        AuthenticationResponse authenticationResponse = 
            authenticationService.emailConfirmationCodeAuthenticate(sessionId, dto.code());
        
        return authenticationResponse.authenticated() 
            ? ResponseEntity.ok().body(authenticationResponse)
            : ResponseEntity.status(HttpStatus.ACCEPTED).body(authenticationResponse);
    }

    @PostMapping("/confirmation-phone-number/{sessionId}")
    public ResponseEntity<?> phoneNumberConfirmationCodeAuthenticate(@PathVariable String sessionId, @Valid @RequestBody ConfirmationCodeDto dto) {
        AuthenticationResponse authenticationResponse = 
            authenticationService.phoneNumberConfirmationCodeAuthenticate(sessionId, dto.code());
        
        return authenticationResponse.authenticated() 
            ? ResponseEntity.ok().body(authenticationResponse)
            : ResponseEntity.status(HttpStatus.ACCEPTED).body(authenticationResponse);
    }

    @PostMapping("/confirmation-authenticator-app/{sessionId}")
    public ResponseEntity<?> authenticatorAppConfirmationCodeAuthenticate(@PathVariable String sessionId, @Valid @RequestBody ConfirmationCodeDto dto) {
        AuthenticationResponse authenticationResponse = 
            authenticationService.authenticatorAppConfirmationCodeAuthenticate(sessionId, dto.code());
        
        return authenticationResponse.authenticated() 
            ? ResponseEntity.ok().body(authenticationResponse)
            : ResponseEntity.status(HttpStatus.ACCEPTED).body(authenticationResponse);
    }

    @PostMapping("/send-email-code/{sessionId}")
    public ResponseEntity<?> sendEmailConfirmationCodeForAuthSession(@PathVariable String sessionId) {
        authenticationService.sendEmailConfirmationCodeForAuthSession(sessionId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/send-phone-number-code/{sessionId}")
    public ResponseEntity<?> sendPhoneNumberConfirmationCodeForAuthSession(@PathVariable String sessionId) {
        authenticationService.sendPhoneNumberConfirmationCodeForAuthSession(sessionId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/refresh-access-token")
    public ResponseEntity<?> refreshAccessToken(@Valid @RequestBody RefreshTokenDto dto) {
        String accessToken = authenticationService.refreshAccessToken(dto.refreshToken());
        return ResponseEntity.ok().body(new AccessTokenDto(accessToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        authenticationService.logout();
        return ResponseEntity.noContent().build();
    }
}
