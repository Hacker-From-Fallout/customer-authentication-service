package com.marketplace.authentication.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.marketplace.authentication.domain.dto.redis.CustomerUserAuthenticationSession;
import com.marketplace.authentication.domain.entities.CustomerUser;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        
        CustomerUser customerUser = (CustomerUser) userDetailsService.loadUserByUsername(username);

        if (passwordEncoder.matches(password, customerUser.getPassword())) {
            if (customerUser.isEmailFactorAuthEnabled() || customerUser.isPhoneNumberFactorAuthEnabled() || customerUser.isAuthenticatorAppFactorAuthEnabled()) {
                return new CustomerUserAuthenticationSession(customerUser);
            }

            return new UsernamePasswordAuthenticationToken(customerUser, null, customerUser.getAuthorities());
        } else {
            throw new BadCredentialsException("Неверные учетные данные");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
