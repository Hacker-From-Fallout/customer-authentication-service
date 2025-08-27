package com.marketplace.authentication.services;

import java.time.LocalDateTime;
import java.util.EnumSet;

import org.springframework.data.domain.Page;

import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;
import com.marketplace.authentication.domain.authorities.CustomerUserRole;
import com.marketplace.authentication.domain.dto.request.CustomerUserCreateDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserFilterDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserUpdateDto;
import com.marketplace.authentication.domain.entities.CustomerUser;

public interface CustomerUserService {
    Page<CustomerUser> findByFilters(CustomerUserFilterDto filters, int page, int size);
    CustomerUser findById(Long id);
    CustomerUser findByUsername(String username);
    CustomerUser findByEmail(String email);
    CustomerUser findByPhoneNumber(String phoneNumber);
    
    CustomerUser createUser(CustomerUserCreateDto dto);
    CustomerUser updateUser(Long id, CustomerUserUpdateDto dto);

    void updateUsername(Long id, String username);
    void updateEmail(Long id, String email);
    void updatePhoneNumber(Long id, String phoneNumber);
    void updateHashPassword(Long id, String hashPassword);
    void updateRoles(Long userId, EnumSet<CustomerUserRole> roles);
    void updateAuthorities(Long userId, EnumSet<CustomerUserAuthority> authorities);
    void updateAccountNonExpired(Long id, boolean accountNonExpired);
    void updateAccountNonLocked(Long id, boolean accountNonLocked);
    void updateCredentialsNonExpired(Long id, boolean credentialsNonExpired);
    void updateEnabled(Long id, boolean enabled);
    void updateEmailFactorAuthEnabled(Long id, boolean enabled);
    void updatePhoneNumberFactorAuthEnabled(Long id, boolean enabled);
    void updateAuthenticatorAppFactorAuthEnabled(Long id, boolean enabled);
    void updateLastLoginDate(Long id, LocalDateTime lastLoginDate);

    void addRole(Long userId, CustomerUserRole role);
    void addRoles(Long userId, EnumSet<CustomerUserRole> roles);
    void removeRole(Long userId, CustomerUserRole role);
    void removeRoles(Long userId, EnumSet<CustomerUserRole> roles);

    void addAuthority(Long userId, CustomerUserAuthority authority);
    void addAuthorities(Long userId, EnumSet<CustomerUserAuthority> authorities);
    void removeAuthority(Long userId, CustomerUserAuthority authority);
    void removeAuthorities(Long userId, EnumSet<CustomerUserAuthority> authorities);

    void isUsernameEmailPhoneAvailable(String username, String email, String phoneNumber);

    void deleteById(Long id);
}
