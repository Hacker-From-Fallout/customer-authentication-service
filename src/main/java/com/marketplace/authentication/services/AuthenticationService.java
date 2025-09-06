package com.marketplace.authentication.services;

import com.marketplace.authentication.domain.dto.request.CustomerUserAuthenticationDto;
import com.marketplace.authentication.domain.dto.response.AuthenticationResponse;

public interface AuthenticationService {
    AuthenticationResponse usernamePasswordAuthenticate(CustomerUserAuthenticationDto dto);
    AuthenticationResponse emailConfirmationCodeAuthenticate(String sessionId, String confirmationCode);
    AuthenticationResponse phoneNumberConfirmationCodeAuthenticate(String sessionId, String confirmationCode);
    AuthenticationResponse authenticatorAppConfirmationCodeAuthenticate(String sessionId, String confirmationCode);
    void sendEmailConfirmationCodeForAuthSession(String sessionId);
    void sendPhoneNumberConfirmationCodeForAuthSession(String sessionId);
    String refreshAccessToken(String refreshToken);
    void logout();
}
