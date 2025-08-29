package com.marketplace.authentication.security;

import java.util.regex.Pattern;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.marketplace.authentication.exception.exceptions.UserNotFoundException;
import com.marketplace.authentication.services.CustomerUserService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class DefaultUserDetailsService implements UserDetailsService {

    private final CustomerUserService customerUserService;
    private final Pattern usernamePattern = Pattern.compile("^[a-zA-Z0-9._-]{3,20}$");
    private final Pattern emailPattern = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private enum LoginType {
        USERNAME,
        EMAIL,
        PHONE_NUMBER;
    }

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        try {
            LoginType loginType = checkLoginType(login);
            switch (loginType) {
                case USERNAME:
                    return customerUserService.findByUsername(login);
                case EMAIL:
                    return customerUserService.findByEmail(login);
                case PHONE_NUMBER:
                    return customerUserService.findByPhoneNumber(login);
                default:
                    throw new UsernameNotFoundException("Invalid login type");
            }
        } catch (UserNotFoundException exception) {
            throw new UsernameNotFoundException(exception.getMessage(), exception);
        }
    }

    private LoginType checkLoginType(String login) {

        if (usernamePattern.matcher(login).matches()) {
            return LoginType.USERNAME;
        } else if (emailPattern.matcher(login).matches()) {
            return LoginType.EMAIL;
        } else {
            return LoginType.PHONE_NUMBER;
        }
    }
}

// private final Pattern phoneNumberPattern = Pattern.compile("^\\+[1-9][0-9]{7,14}$");
