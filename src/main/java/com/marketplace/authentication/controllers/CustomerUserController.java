package com.marketplace.authentication.controllers;

import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.marketplace.authentication.domain.dto.request.AccountNonExpiredDto;
import com.marketplace.authentication.domain.dto.request.AccountNonLockedDto;
import com.marketplace.authentication.domain.dto.request.CredentialsNonExpiredDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserAuthoritiesDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserAuthorityDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserCreateDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserFilterDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserRoleDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserRolesDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserUpdateDto;
import com.marketplace.authentication.domain.dto.request.EmailDto;
import com.marketplace.authentication.domain.dto.request.EnabledDto;
import com.marketplace.authentication.domain.dto.request.LastLoginDateDto;
import com.marketplace.authentication.domain.dto.request.PasswordDto;
import com.marketplace.authentication.domain.dto.request.PhoneNumberDto;
import com.marketplace.authentication.domain.dto.request.UsernameDto;
import com.marketplace.authentication.domain.dto.response.AuthenticatorAppConfirmationCodeSecret;
import com.marketplace.authentication.domain.dto.response.CustomerUserResponseDto;
import com.marketplace.authentication.domain.entities.CustomerUser;
import com.marketplace.authentication.services.CustomerUserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class CustomerUserController {

    private final CustomerUserService customerUserService;

    @GetMapping
    public ResponseEntity<Page<CustomerUserResponseDto>> getAll(
            @ModelAttribute CustomerUserFilterDto filters,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        Page<CustomerUser> pageResult = customerUserService.findByFilters(filters, page, size);
        Page<CustomerUserResponseDto> dtosPage = pageResult.map(CustomerUserResponseDto::from);
        return ResponseEntity.ok(dtosPage);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        CustomerUser customerUser = customerUserService.findById(id);
        return ResponseEntity.status(HttpStatus.OK).body(
                CustomerUserResponseDto.from(customerUser));
    }

    @GetMapping("/username/{username}")
    public ResponseEntity<?> getUserByUsername(@PathVariable String username) {
        CustomerUser customerUser = customerUserService.findByUsername(username);
        return ResponseEntity.status(HttpStatus.OK).body(
                CustomerUserResponseDto.from(customerUser));
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<?> getUserByEmail(@PathVariable String email) {
        CustomerUser customerUser = customerUserService.findByEmail(email);
        return ResponseEntity.status(HttpStatus.OK).body(
                CustomerUserResponseDto.from(customerUser));
    }

    @GetMapping("/phone/{phoneNumber}")
    public ResponseEntity<?> getUserByPhoneNumber(@PathVariable String phoneNumber) {
        CustomerUser customerUser = customerUserService.findByPhoneNumber(phoneNumber);
        return ResponseEntity.status(HttpStatus.OK).body(
                CustomerUserResponseDto.from(customerUser));
    }

    @PostMapping
    public ResponseEntity<?> createUser(@Valid @RequestBody CustomerUserCreateDto dto, 
                            BindingResult bindingResult) throws BindException {
        if (bindingResult.hasErrors()) {
            if (bindingResult instanceof BindException error) {
                throw error;
            } else {
                throw new BindException(bindingResult);
            }
        }

        CustomerUser customerUser = customerUserService.createUser(dto);
        
        return ResponseEntity.status(HttpStatus.CREATED).body(
                CustomerUserResponseDto.from(customerUser));
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @Valid @RequestBody CustomerUserUpdateDto dto, 
                            BindingResult bindingResult) throws BindException {
        if (bindingResult.hasErrors()) {
            if (bindingResult instanceof BindException error) {
                throw error;
            } else {
                throw new BindException(bindingResult);
            }
        }

        CustomerUser customerUser = customerUserService.updateUser(id, dto);
        
        return ResponseEntity.status(HttpStatus.OK).body(
                CustomerUserResponseDto.from(customerUser));
    }

    @PatchMapping("/{id}/username")
    public ResponseEntity<?> updateUsername(@PathVariable Long id, @Valid @RequestBody UsernameDto dto) {
        customerUserService.updateUsername(id, dto.username());
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/email")
    public ResponseEntity<?> updateEmail(@PathVariable Long id, @Valid @RequestBody EmailDto dto) {
        customerUserService.updateEmail(id, dto.email());
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/phone-number")
    public ResponseEntity<?> updatePhoneNumber(@PathVariable Long id, @Valid @RequestBody PhoneNumberDto dto) {
        customerUserService.updatePhoneNumber(id, dto.phoneNumber());
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/password")
    public ResponseEntity<?> updatePassword(@PathVariable Long id, @Valid @RequestBody PasswordDto dto) {
        customerUserService.updateHashPassword(id, dto.password());
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{userId}/roles")
    public ResponseEntity<?> updateRoles(@PathVariable Long userId, @Valid @RequestBody CustomerUserRolesDto dto) {
        customerUserService.updateRoles(userId, dto.roles());
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{userId}/authorities")
    public ResponseEntity<?> updateAuthorities(@PathVariable Long userId, @Valid @RequestBody CustomerUserAuthoritiesDto dto) {
        customerUserService.updateAuthorities(userId, dto.authorities());
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/accountNonExpired")
    public ResponseEntity<?> updateAccountNonExpired(@PathVariable Long id, @Valid @RequestBody AccountNonExpiredDto dto) {
        customerUserService.updateAccountNonExpired(id, dto.accountNonExpired().booleanValue());
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/account-non-locked")
    public ResponseEntity<?> updateAccountNonLocked(@PathVariable Long id, @Valid @RequestBody AccountNonLockedDto dto) {
        customerUserService.updateAccountNonLocked(id, dto.accountNonLocked().booleanValue());
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/credentials-non-expired")
    public ResponseEntity<?> updateCredentialsNonExpired(@PathVariable Long id, @Valid @RequestBody CredentialsNonExpiredDto dto) {
        customerUserService.updateCredentialsNonExpired(id, dto.credentialsNonExpired().booleanValue());
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/enabled")
    public ResponseEntity<?> updateEnabled(@PathVariable Long id, @Valid @RequestBody EnabledDto dto) {
        customerUserService.updateEnabled(id, dto.enabled().booleanValue());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/email-factor-auth-enable")
    public ResponseEntity<?> enableEmailFactorAuth(@PathVariable Long id) {
        customerUserService.enableEmailFactorAuth(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/email-factor-auth-disable")
    public ResponseEntity<?> disableEmailFactorAuth(@PathVariable Long id) {
        customerUserService.disableEmailFactorAuth(id);
        return ResponseEntity.noContent().build();
    }


    @PostMapping("/{id}/phone-number-factor-auth-enable")
    public ResponseEntity<?> enablePhoneNumberFactorAuth(@PathVariable Long id) {
        customerUserService.enablePhoneNumberFactorAuth(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/phone-number-factor-auth-disable")
    public ResponseEntity<?> disablePhoneNumberFactorAuth(@PathVariable Long id) {
        customerUserService.disablePhoneNumberFactorAuth(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/authenticator-app-factor-auth-enable")
    public ResponseEntity<?> enableAuthenticatorAppFactorAuth(@PathVariable Long id) {
        String authenticatorAppConfirmationCodeSecret = 
            customerUserService.enableAuthenticatorAppFactorAuth(id);

        return ResponseEntity.status(HttpStatus.OK).body(
            new AuthenticatorAppConfirmationCodeSecret(authenticatorAppConfirmationCodeSecret));
    }

    @PostMapping("/{id}/authenticator-app-factor-auth-disable")
    public ResponseEntity<?> disableAuthenticatorAppFactorAuth(@PathVariable Long id) {
        customerUserService.disableAuthenticatorAppFactorAuth(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/last-login-date")
    public ResponseEntity<?> updateLastLoginDate(@PathVariable Long id, @Valid @RequestBody LastLoginDateDto dto) {
        customerUserService.updateLastLoginDate(id, dto.lastLoginDate());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{userId}/roles")
    public ResponseEntity<?> addRole(@PathVariable Long userId, @Valid @RequestBody CustomerUserRoleDto dto) {
        customerUserService.addRole(userId, dto.role());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{userId}/roles/batch")
    public ResponseEntity<?> addRoles(@PathVariable Long userId, @Valid @RequestBody CustomerUserRolesDto dto) {
        customerUserService.addRoles(userId, dto.roles());
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{userId}/roles")
    public ResponseEntity<?> removeRole(@PathVariable Long userId, @Valid @RequestBody CustomerUserRoleDto dto) {
        customerUserService.removeRole(userId, dto.role());
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{userId}/roles/batch")
    public ResponseEntity<?> removeRoles(@PathVariable Long userId, @Valid @RequestBody CustomerUserRolesDto dto) {
        customerUserService.removeRoles(userId, dto.roles());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{userId}/authorities")
    public ResponseEntity<?> addAuthority(@PathVariable Long userId, @Valid @RequestBody CustomerUserAuthorityDto dto) {
        customerUserService.addAuthority(userId, dto.authority());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{userId}/authorities/batch")
    public ResponseEntity<?> addAuthorities(@PathVariable Long userId, @Valid @RequestBody CustomerUserAuthoritiesDto dto) {
        customerUserService.addAuthorities(userId, dto.authorities());
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{userId}/authorities")
    public ResponseEntity<?> removeAuthority(@PathVariable Long userId, @Valid @RequestBody CustomerUserAuthorityDto dto) {
        customerUserService.removeAuthority(userId, dto.authority());
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{userId}/authorities/batch")
    public ResponseEntity<?> removeAuthorities(@PathVariable Long userId, @Valid @RequestBody CustomerUserAuthoritiesDto dto) {
        customerUserService.removeAuthorities(userId, dto.authorities());
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        customerUserService.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}
