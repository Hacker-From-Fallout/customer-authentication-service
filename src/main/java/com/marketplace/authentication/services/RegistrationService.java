package com.marketplace.authentication.services;

import java.util.UUID;

import com.marketplace.authentication.domain.dto.request.ConfirmationRegistrarionCodesDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserCreateDto;
import com.marketplace.authentication.security.Tokens;

public interface RegistrationService {
    UUID initiateRegistration(CustomerUserCreateDto dto);
    Tokens confirmationRegistration(String sessionId, ConfirmationRegistrarionCodesDto dto);
    void resendConfirmationRegistrationCodes(String sessionId);
}
