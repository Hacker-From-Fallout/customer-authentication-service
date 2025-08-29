package com.marketplace.authentication.domain.dto.response;

import com.marketplace.authentication.security.Tokens;

public record AuthenticationResponse(
    String sessionId,
    boolean authenticated,
    boolean emailFactorAuthPassed,
    boolean phoneNumberFactorAuthPassed,
    boolean authenticatorAppFactorAuthPassed,
    Tokens tokens
) {}
