package com.marketplace.authentication.security;

import com.marketplace.authentication.domain.entities.CustomerUser;

public interface MultiFactorAuthProvider {

    void sendConfirmationCode(CustomerUser customerUser);
    boolean verifyConfirmationCode(CustomerUser customerUser, String code);
    String getType();
}
