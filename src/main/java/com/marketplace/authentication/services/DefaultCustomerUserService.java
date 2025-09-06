package com.marketplace.authentication.services;

import java.time.LocalDateTime;
import java.util.EnumSet;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;
import com.marketplace.authentication.domain.authorities.CustomerUserRole;
import com.marketplace.authentication.domain.dto.kafka.CustomerProfileCreateDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserCreateDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserFilterDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserUpdateDto;
import com.marketplace.authentication.domain.entities.CustomerUser;
import com.marketplace.authentication.exception.exceptions.AlreadyExistsException;
import com.marketplace.authentication.exception.exceptions.UserNotFoundException;
import com.marketplace.authentication.producers.CustomerProfileProducer;
import com.marketplace.authentication.repositories.CustomerUserRepository;
import com.marketplace.authentication.repositories.specifications.CustomerUserSpecifications;
import com.marketplace.authentication.security.BlacklistTokenService;
import com.marketplace.authentication.security.CryptoUtils;
import com.marketplace.authentication.security.OtpService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class DefaultCustomerUserService implements CustomerUserService {

    private final CustomerUserRepository customerUserRepository;
    private final CustomerProfileProducer customerProfileProducer;
    private final BlacklistTokenService blacklistTokenService;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;
    private final CryptoUtils cryptoUtils;

    @Override
    @Transactional(readOnly = true)
    public Page<CustomerUser> findByFilters(CustomerUserFilterDto filters, int page, int size) {
        Specification<CustomerUser> specification = (root, query, criteriaBuilder) -> criteriaBuilder.conjunction();

        if (filters.username() != null && !filters.username().isEmpty()) {
            specification = specification.and(CustomerUserSpecifications.hasUsername(filters.username()));
        }
        if (filters.email() != null && !filters.email().isEmpty()) {
            specification = specification.and(CustomerUserSpecifications.hasEmail(filters.email()));
        }
        if (filters.phoneNumber() != null && !filters.phoneNumber().isEmpty()) {
            specification = specification.and(CustomerUserSpecifications.hasPhoneNumber(filters.phoneNumber()));
        }

        Pageable pageable = PageRequest.of(page, size);
        return customerUserRepository.findAll(specification, pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public CustomerUser findById(Long id) {
        return customerUserRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException("Пользователь не найден с id: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public CustomerUser findByUsername(String username) {
        return customerUserRepository.findByUsername(username)
            .orElseThrow(() -> new UserNotFoundException("Пользователь не найден с username: " + username));
    
    }

    @Override
    @Transactional(readOnly = true)
    public CustomerUser findByEmail(String email) {
        return customerUserRepository.findByEmail(email)
            .orElseThrow(() -> new UserNotFoundException("Пользователь не найден с email: " + email));
    }

    @Override
    @Transactional(readOnly = true)
    public CustomerUser findByPhoneNumber(String phoneNumber) {
        return customerUserRepository.findByPhoneNumber(phoneNumber)
            .orElseThrow(() -> new UserNotFoundException("Пользователь не найден с phoneNumber: " + phoneNumber));
    }

    @Override
    @Transactional
    public CustomerUser createUser(CustomerUserCreateDto customerDto) {
        validateUniqueFields(customerDto);

        CustomerUser customerUser = buildCustomerUser(customerDto);
        customerUser = customerUserRepository.save(customerUser);
        
        CustomerProfileCreateDto profileDto = new CustomerProfileCreateDto(
            customerUser.getId(),
            customerDto.firstName(),
            customerDto.lastName(),
            customerDto.username(),
            customerDto.email(),
            customerDto.phoneNumber());

        customerProfileProducer.createProfile(profileDto);

        return customerUser;
    }

    private void validateUniqueFields(CustomerUserCreateDto dto) {
        existsByUsername(dto.username());
        existsByEmail(dto.email());
        existsByPhoneNumber(dto.phoneNumber());
    }

    private CustomerUser buildCustomerUser(CustomerUserCreateDto dto) {
        return CustomerUser.builder()
                .username(dto.username())
                .email(dto.email())
                .phoneNumber(dto.phoneNumber())
                .hashPassword(passwordEncoder.encode(dto.password()))
                .roles(dto.roles())
                .authorities(dto.authorities())
                .accountNonExpired(dto.accountNonExpired())
                .accountNonLocked(dto.accountNonLocked())
                .credentialsNonExpired(dto.credentialsNonExpired())
                .enabled(dto.enabled())
                .emailFactorAuthEnabled(dto.emailFactorAuthEnabled())
                .phoneNumberFactorAuthEnabled(dto.phoneNumberFactorAuthEnabled())
                .authenticatorAppFactorAuthEnabled(dto.authenticatorAppFactorAuthEnabled())
                .build();
    }

    @Override
    @Transactional()
    public CustomerUser updateUser(Long id, CustomerUserUpdateDto dto) {
        CustomerUser customerUser = customerUserRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("Пользователь не найден с id: " + id));

        if (dto.username() != null) {
            existsByUsername(dto.username());
            customerUser.setUsername(dto.username());;
            customerProfileProducer.updateUsername(id, dto.username());
        }
        if (dto.email() != null) {
            existsByEmail(dto.email());
            customerUser.setEmail(dto.email());
            customerProfileProducer.updateEmail(id, dto.email());
        }
        if (dto.phoneNumber() != null) {
            existsByPhoneNumber(dto.phoneNumber());
            customerUser.setPhoneNumber(dto.phoneNumber());
            customerProfileProducer.updatePhoneNumber(id, dto.phoneNumber());
        }
        if (dto.password() != null) {
            customerUser.setHashPassword(passwordEncoder.encode(dto.password()));
        }
        if(dto.roles() != null) {
            customerUser.setRoles(dto.roles());
            addTokenInBlacklist(id);
        }
        if (dto.authorities() != null) {
            customerUser.setAuthorities(dto.authorities());
            addTokenInBlacklist(id);
        }
        if (dto.accountNonExpired() != null) {
            customerUser.setAccountNonExpired(dto.accountNonExpired().booleanValue());
        }
        if (dto.accountNonLocked() != null) {
            customerUser.setAccountNonLocked(dto.accountNonLocked().booleanValue());
        }
        if (dto.credentialsNonExpired() != null) {
            customerUser.setCredentialsNonExpired(dto.credentialsNonExpired().booleanValue());
        }
        if (dto.enabled() != null) {
            customerUser.setEnabled(dto.enabled().booleanValue());
        }
        if (dto.emailFactorAuthEnabled() != null) {
            customerUser.setEmailFactorAuthEnabled(dto.emailFactorAuthEnabled().booleanValue());
        }
        if (dto.phoneNumberFactorAuthEnabled() != null) {
            customerUser.setPhoneNumberFactorAuthEnabled(dto.phoneNumberFactorAuthEnabled());
        }
        if (dto.authenticatorAppFactorAuthEnabled() != null) {
            customerUser.setAuthenticatorAppFactorAuthEnabled(dto.authenticatorAppFactorAuthEnabled());
        }
        if (dto.lastLoginDate() != null) {
            customerUser.setLastLoginDate(dto.lastLoginDate());
        }

        return customerUserRepository.save(customerUser);
    }


    @Override
    @Transactional
    public void updateUsername(Long id, String username) {
        existsByUsername(username);
        customerUserRepository.updateUsername(id, username);
        customerProfileProducer.updateUsername(id, username);
    }

    @Override
    @Transactional
    public void updateEmail(Long id, String email) {
        existsByEmail(email);
        customerUserRepository.updateEmail(id, email);
        customerProfileProducer.updateEmail(id, email);
    }

    @Override
    @Transactional
    public void updatePhoneNumber(Long id, String phoneNumber) {
        existsByPhoneNumber(phoneNumber);
        customerUserRepository.updatePhoneNumber(id, phoneNumber);
        customerProfileProducer.updatePhoneNumber(id, phoneNumber);
    }

    @Override
    @Transactional
    public void updateHashPassword(Long id, String hashPassword) {
        customerUserRepository.updateHashPassword(id, hashPassword);
    }

    @Override
    @Transactional
    public void updateRoles(Long userId, EnumSet<CustomerUserRole> roles) {
        customerUserRepository.deleteAllRoles(userId);
        addTokenInBlacklist(userId);

        for (CustomerUserRole role : roles) {
            customerUserRepository.addRole(userId, role.name());
        }
    }

    @Override
    @Transactional
    public void updateAuthorities(Long userId, EnumSet<CustomerUserAuthority> authorities) {
        customerUserRepository.deleteAllAuthorities(userId);
        addTokenInBlacklist(userId);

        for (CustomerUserAuthority authority : authorities) {
            customerUserRepository.addAuthority(userId, authority.name());
        }
    }

    @Override
    @Transactional
    public void updateAccountNonExpired(Long id, boolean accountNonExpired) {
        customerUserRepository.updateAccountNonExpired(id, accountNonExpired);
    }

    @Override
    @Transactional
    public void updateAccountNonLocked(Long id, boolean accountNonLocked) {
        customerUserRepository.updateAccountNonLocked(id, accountNonLocked);
    }

    @Override
    @Transactional
    public void updateCredentialsNonExpired(Long id, boolean credentialsNonExpired) {
        customerUserRepository.updateCredentialsNonExpired(id, credentialsNonExpired);
    }

    @Override
    @Transactional
    public void updateEnabled(Long id, boolean enabled) {
        customerUserRepository.updateEnabled(id, enabled);
    }

    @Override
    @Transactional
    public void enableEmailFactorAuth(Long id) {

        String emailConfirmationCodeSecret = otpService.generateSecret();
        String encryptedEmailConfirmationCodeSecret = cryptoUtils.encrypt(emailConfirmationCodeSecret);

        customerUserRepository.updateEmailFactorAuthEnabled(id, true);
        customerUserRepository.updateEncryptedEmailConfirmationCodeSecret(id, encryptedEmailConfirmationCodeSecret);
    }

    @Override
    @Transactional
    public void enablePhoneNumberFactorAuth(Long id) {

        String phoneNumberConfirmationCodeSecret = otpService.generateSecret();
        String encryptedPhoneNumberConfirmationCodeSecret = cryptoUtils.encrypt(phoneNumberConfirmationCodeSecret);

        customerUserRepository.updatePhoneNumberFactorAuthEnabled(id, true);
        customerUserRepository.updateEncryptedPhoneNumberConfirmationCodeSecret(id, encryptedPhoneNumberConfirmationCodeSecret);
    }

    @Override
    @Transactional
    public String enableAuthenticatorAppFactorAuth(Long id) {

        String authenticatorAppConfirmationCodeSecret = otpService.generateSecret();
        String encryptedAuthenticatorAppConfirmationCodeSecret = cryptoUtils.encrypt(authenticatorAppConfirmationCodeSecret);

        customerUserRepository.updateAuthenticatorAppFactorAuthEnabled(id, true);
        customerUserRepository.updateEncryptedAuthenticatorAppConfirmationCodeSecret(id, encryptedAuthenticatorAppConfirmationCodeSecret);

        return authenticatorAppConfirmationCodeSecret;
    }

    @Override
    @Transactional
    public void disableEmailFactorAuth(Long id) {
        customerUserRepository.updateEmailFactorAuthEnabled(id, false);
        customerUserRepository.updateEncryptedEmailConfirmationCodeSecret(id, null);
    }

    @Override
    @Transactional
    public void disablePhoneNumberFactorAuth(Long id) {
        customerUserRepository.updatePhoneNumberFactorAuthEnabled(id, false);
        customerUserRepository.updateEncryptedPhoneNumberConfirmationCodeSecret(id, null);
    }

    @Override
    @Transactional
    public void disableAuthenticatorAppFactorAuth(Long id) {
        customerUserRepository.updateAuthenticatorAppFactorAuthEnabled(id, false);
        customerUserRepository.updateEncryptedAuthenticatorAppConfirmationCodeSecret(id, null);
    }

    @Override
    @Transactional
    public void updateLastLoginDate(Long id, LocalDateTime lastLoginDate) {
        customerUserRepository.updateLastLoginDate(id, lastLoginDate);
    }

    @Override
    @Transactional
    public void addRole(Long userId, CustomerUserRole role) {
        customerUserRepository.addRole(userId, role.name());
        addTokenInBlacklist(userId);
    }
    
    @Override
    @Transactional
    public void addRoles(Long userId, EnumSet<CustomerUserRole> roles) {
        addTokenInBlacklist(userId);

        for (CustomerUserRole role : roles) {
            customerUserRepository.addRole(userId, role.name());
        }
    }

    @Override
    @Transactional
    public void removeRole(Long userId, CustomerUserRole role) {
        customerUserRepository.removeRole(userId, role.name());
        addTokenInBlacklist(userId);
    }

    @Override
    @Transactional
    public void removeRoles(Long userId, EnumSet<CustomerUserRole> roles) {
        addTokenInBlacklist(userId);

        for (CustomerUserRole role : roles) {
            customerUserRepository.removeRole(userId, role.name());
        }
    }

    @Override
    @Transactional
    public void addAuthority(Long userId, CustomerUserAuthority authority) {
        customerUserRepository.addAuthority(userId, authority.name());
        addTokenInBlacklist(userId);
    }

    @Override
    @Transactional
    public void addAuthorities(Long userId, EnumSet<CustomerUserAuthority> authorities) {
        addTokenInBlacklist(userId);

        for (CustomerUserAuthority authority : authorities) {
            customerUserRepository.addAuthority(userId, authority.name());
        }
    }

    @Override
    @Transactional
    public void removeAuthority(Long userId, CustomerUserAuthority authority) {
        customerUserRepository.removeAuthority(userId , authority.name());
        addTokenInBlacklist(userId);
    }

    @Override
    @Transactional
    public void removeAuthorities(Long userId, EnumSet<CustomerUserAuthority> authorities) {
        addTokenInBlacklist(userId);

        for (CustomerUserAuthority authority : authorities) {
            customerUserRepository.removeAuthority(userId, authority.name());
        }
    }

    public void isUsernameEmailPhoneAvailable(String username, String email, String phoneNumber) {
        existsByUsername(username);
        existsByEmail(email);
        existsByPhoneNumber(phoneNumber);
    }

    @Override
    @Transactional
    public void deleteById(Long id){
        customerUserRepository.deleteById(id);
        customerProfileProducer.deleteProfile(id);
    }

    private void existsByUsername(String username) {
        if (customerUserRepository.existsByUsername(username)) {
            throw new AlreadyExistsException("Пользователь с username " + username + " уже существует");
        }
    }

    private void existsByEmail(String email) {
        if (customerUserRepository.existsByEmail(email)) {
            throw new AlreadyExistsException("Пользователь с email " + email + " уже существует");
        }
    }

    private void existsByPhoneNumber(String phoneNumber) {
        if (customerUserRepository.existsByPhoneNumber(phoneNumber)) {
            throw new AlreadyExistsException("Пользователь с phoneNumber " + phoneNumber + " уже существует");
        }
    }

    private void addTokenInBlacklist(Long id)  {
        String tokenId = customerUserRepository.getTokenId(id);
        blacklistTokenService.saveToken(tokenId);
    }
}
