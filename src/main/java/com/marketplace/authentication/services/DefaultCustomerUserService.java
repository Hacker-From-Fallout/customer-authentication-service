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
import com.marketplace.authentication.producers.CustomerUserProducer;
import com.marketplace.authentication.repositories.CustomerUserRepository;
import com.marketplace.authentication.repositories.specifications.CustomerUserSpecifications;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class DefaultCustomerUserService implements CustomerUserService {

    private final CustomerUserRepository customerUserRepository;
    private final CustomerUserProducer customerUserProducer;
    private final PasswordEncoder bCyPasswordEncoder;

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

        customerUserProducer.createProfile(profileDto);

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
                .hashPassword(bCyPasswordEncoder.encode(dto.password()))
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
            customerUserProducer.updateUsername(id, dto.username());
        }
        if (dto.email() != null) {
            existsByEmail(dto.email());
            customerUser.setEmail(dto.email());
            customerUserProducer.updateEmail(id, dto.email());
        }
        if (dto.phoneNumber() != null) {
            existsByPhoneNumber(dto.phoneNumber());
            customerUser.setPhoneNumber(dto.phoneNumber());
            customerUserProducer.updatePhoneNumber(id, dto.phoneNumber());
        }
        if (dto.password() != null) {
            customerUser.setHashPassword(bCyPasswordEncoder.encode(dto.password()));
        }
        if(dto.roles() != null) {
            customerUser.setRoles(dto.roles());
        }
        if (dto.authorities() != null) {
            customerUser.setAuthorities(dto.authorities());
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
        ensureUserExists(id);
        existsByUsername(username);
        customerUserRepository.updateUsername(id, username);
        customerUserProducer.updateUsername(id, username);
    }

    @Override
    @Transactional
    public void updateEmail(Long id, String email) {
        ensureUserExists(id);
        existsByEmail(email);
        customerUserRepository.updateEmail(id, email);
        customerUserProducer.updateEmail(id, email);
    }

    @Override
    @Transactional
    public void updatePhoneNumber(Long id, String phoneNumber) {
        ensureUserExists(id);
        existsByPhoneNumber(phoneNumber);
        customerUserRepository.updatePhoneNumber(id, phoneNumber);
        customerUserProducer.updatePhoneNumber(id, phoneNumber);
    }

    @Override
    @Transactional
    public void updateHashPassword(Long id, String hashPassword) {
        ensureUserExists(id);
        customerUserRepository.updateHashPassword(id, hashPassword);
    }

    @Override
    @Transactional
    public void updateRoles(Long userId, EnumSet<CustomerUserRole> roles) {
        ensureUserExists(userId);
        customerUserRepository.deleteAllRoles(userId);

        for (CustomerUserRole role : roles) {
            customerUserRepository.addRole(userId, role.name());
        }
    }

    @Override
    @Transactional
    public void updateAuthorities(Long userId, EnumSet<CustomerUserAuthority> authorities) {
        ensureUserExists(userId);
        customerUserRepository.deleteAllAuthorities(userId);

        for (CustomerUserAuthority authority : authorities) {
            customerUserRepository.addAuthority(userId, authority.name());
        }
    }

    @Override
    @Transactional
    public void updateAccountNonExpired(Long id, boolean accountNonExpired) {
        ensureUserExists(id);
        customerUserRepository.updateAccountNonExpired(id, accountNonExpired);
    }

    @Override
    @Transactional
    public void updateAccountNonLocked(Long id, boolean accountNonLocked) {
        ensureUserExists(id);
        customerUserRepository.updateAccountNonLocked(id, accountNonLocked);
    }

    @Override
    @Transactional
    public void updateCredentialsNonExpired(Long id, boolean credentialsNonExpired) {
        ensureUserExists(id);
        customerUserRepository.updateCredentialsNonExpired(id, credentialsNonExpired);
    }

    @Override
    @Transactional
    public void updateEnabled(Long id, boolean enabled) {
        ensureUserExists(id);
        customerUserRepository.updateEnabled(id, enabled);
    }

    @Override
    @Transactional
    public void updateEmailFactorAuthEnabled(Long id, boolean enabled) {
        ensureUserExists(id);
        customerUserRepository.updateEmailFactorAuthEnabled(id, enabled);
    }

    @Override
    @Transactional
    public void updatePhoneNumberFactorAuthEnabled(Long id, boolean enabled) {
        ensureUserExists(id);
        customerUserRepository.updatePhoneNumberFactorAuthEnabled(id, enabled);
    }

    @Override
    @Transactional
    public void updateAuthenticatorAppFactorAuthEnabled(Long id, boolean enabled) {
        ensureUserExists(id);
        customerUserRepository.updateAuthenticatorAppFactorAuthEnabled(id, enabled);
    }

    @Override
    @Transactional
    public void updateLastLoginDate(Long id, LocalDateTime lastLoginDate) {
        ensureUserExists(id);
        customerUserRepository.updateLastLoginDate(id, lastLoginDate);
    }

    @Override
    @Transactional
    public void addRole(Long userId, CustomerUserRole role) {
        ensureUserExists(userId);
        customerUserRepository.addRole(userId, role.name());
    }
    
    @Override
    @Transactional
    public void addRoles(Long userId, EnumSet<CustomerUserRole> roles) {
        ensureUserExists(userId);
        for (CustomerUserRole role : roles) {
            customerUserRepository.addRole(userId, role.name());
        }
    }

    @Override
    @Transactional
    public void removeRole(Long userId, CustomerUserRole role) {
        ensureUserExists(userId);
        customerUserRepository.removeRole(userId, role.name());
    }

    @Override
    @Transactional
    public void removeRoles(Long userId, EnumSet<CustomerUserRole> roles) {
        ensureUserExists(userId);
        for (CustomerUserRole role : roles) {
            customerUserRepository.removeRole(userId, role.name());
        }
    }

    @Override
    @Transactional
    public void addAuthority(Long userId, CustomerUserAuthority authority) {
        ensureUserExists(userId);
        customerUserRepository.addAuthority(userId, authority.name());
    }

    @Override
    @Transactional
    public void addAuthorities(Long userId, EnumSet<CustomerUserAuthority> authorities) {
        ensureUserExists(userId);
        for (CustomerUserAuthority authority : authorities) {
            customerUserRepository.addAuthority(userId, authority.name());
        }
    }

    @Override
    @Transactional
    public void removeAuthority(Long userId, CustomerUserAuthority authority) {
        ensureUserExists(userId);
        customerUserRepository.removeAuthority(userId , authority.name());
    }

    @Override
    @Transactional
    public void removeAuthorities(Long userId, EnumSet<CustomerUserAuthority> authorities) {
        ensureUserExists(userId);
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
        customerUserProducer.deleteProfile(id);
    }

    private void ensureUserExists(Long id) {
        if (!customerUserRepository.existsById(id)) {
            throw new UserNotFoundException("Пользователь не найден с id: " + id);
        }
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
}
