package com.marketplace.authentication.security;

import com.marketplace.authentication.domain.dto.kafka.EmailConfirmationCodeDto;
import com.marketplace.authentication.domain.entities.CustomerUser;
import com.marketplace.authentication.producers.ConfirmationProducer;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class EmailFactorAuthProvider implements MultiFactorAuthProvider {

    private final ConfirmationProducer confirmationProducer;
    private final CryptoUtils cryptoUtils;
    private final OtpService otpService;

    @Override
    public void sendConfirmationCode(CustomerUser customerUser) {

        String encryptedEmailConfirmationCodeSecret = customerUser.getEncryptedEmailConfirmationCodeSecret();
        String emailConfirmationCodeSecret = cryptoUtils.decrypt(encryptedEmailConfirmationCodeSecret);
        EmailConfirmationCodeDto emailConfirmationCodeDto = 
            new EmailConfirmationCodeDto(customerUser.getEmail(), 
                otpService.generateCurrentCode(emailConfirmationCodeSecret));

        confirmationProducer.emailConfirmation(emailConfirmationCodeDto);
    }

    @Override
    public boolean verifyConfirmationCode(CustomerUser customerUser, String code) {

        String encryptedEmailConfirmationCodeSecret = customerUser.getEncryptedEmailConfirmationCodeSecret();
        String emailConfirmationCodeSecret = cryptoUtils.decrypt(encryptedEmailConfirmationCodeSecret);

        return otpService.verifyCode(code, emailConfirmationCodeSecret);
    }

    @Override
    public String getType() {
        return "EMAIL";
    }
}
