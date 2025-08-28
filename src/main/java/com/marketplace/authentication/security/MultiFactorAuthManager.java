package com.marketplace.authentication.security;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.marketplace.authentication.domain.entities.CustomerUser;

@Service
public class MultiFactorAuthManager {

    private final Map<String, MultiFactorAuthProvider> providers;

    public MultiFactorAuthManager(List<MultiFactorAuthProvider> providerList) {
        this.providers = providerList.stream()
            .collect(Collectors.toMap(MultiFactorAuthProvider::getType, Function.identity()));
    }

    public void initiateMultiFactorAuth(CustomerUser customerUser, List<String> mfaTypes) {
        for (String type : mfaTypes) {
            MultiFactorAuthProvider provider = providers.get(type);
            if (provider != null) {
                provider.sendConfirmationCode(customerUser);
            }
        }
    }

    public boolean verifyCode(CustomerUser customerUser, String type, String code) {
        MultiFactorAuthProvider provider = providers.get(type);
        if (provider != null) {
            return provider.verifyConfirmationCode(customerUser, code);
        }
        return false;
    }
}
