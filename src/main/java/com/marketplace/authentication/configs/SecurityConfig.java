package com.marketplace.authentication.configs;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.marketplace.authentication.security.AuthenticatorAppConfirmationCodeAuthenticationProvider;
import com.marketplace.authentication.security.CryptoUtils;
import com.marketplace.authentication.security.DefaultAuthenticationManager;
import com.marketplace.authentication.security.EmailConfirmationCodeAuthenticationProvider;
import com.marketplace.authentication.security.OtpService;
import com.marketplace.authentication.security.PhoneNumberConfirmationCodeAuthenticationProvider;
import com.marketplace.authentication.security.UsernamePasswordAuthenticationProvider;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                .anyRequest().permitAll())
                .csrf(CsrfConfigurer::disable);

        return http.build();
    } 

    @Bean 
    public AuthenticationProvider usernamePasswordAuthenticationProvider() {
        return new UsernamePasswordAuthenticationProvider(userDetailsService, passwordEncoder);
    }

    @Bean
    public AuthenticationProvider emailConfirmationCodeAuthenticationProvider() {
        return new EmailConfirmationCodeAuthenticationProvider(otpService, cryptoUtils);
    }

    @Bean
    public AuthenticationProvider phoneAuthenticationProvider() {
        return new PhoneNumberConfirmationCodeAuthenticationProvider(otpService, cryptoUtils);
    }

    @Bean
    public AuthenticationProvider appAuthenticationProvider() {
        return new AuthenticatorAppConfirmationCodeAuthenticationProvider(otpService, cryptoUtils);
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers) {
        return new DefaultAuthenticationManager(providers);
    }
}
