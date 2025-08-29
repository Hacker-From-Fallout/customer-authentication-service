package com.marketplace.authentication.domain.entities;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;
import com.marketplace.authentication.domain.authorities.CustomerUserRole;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@RequiredArgsConstructor
@Builder
@Table(name = "customer_users", indexes = {
    @Index(name = "idx_customer_username", columnList = "username"),
    @Index(name = "idx_customer_email", columnList = "email"),
    @Index(name = "idx_customer_phone_number", columnList = "phone_number"),
})
public class CustomerUser implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "customer_user_id_sequence")
    @SequenceGenerator(name = "customer_user_id_sequence", sequenceName = "customer_user_id_sequence", allocationSize = 1)
    @Column(name = "id", nullable = false)
    @Setter(AccessLevel.NONE)
    private Long id;

    @NonNull
    @Column(name = "username", unique = true, nullable = false)
    private String username;

    @NonNull
    @Column(name = "email", unique = true, nullable = false)
    private String email;

    @NonNull
    @Column(name = "phone_number", unique = true, nullable = false)
    private String phoneNumber;

    @NonNull
    @Column(name = "hash_password", nullable = false)
    private String hashPassword;

    @NonNull
    @ElementCollection(targetClass = CustomerUserRole.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "customer_user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "roles", nullable = false)
    private Set<CustomerUserRole> roles;

    @NonNull
    @ElementCollection(targetClass = CustomerUserAuthority.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "customer_user_authorities", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "authorities", nullable = false)
    private Set<CustomerUserAuthority> authorities;

    @Column(name = "account_non_expired")
    private boolean accountNonExpired;

    @Column(name = "account_non_locked")
    private boolean accountNonLocked;

    @Column(name = "credentials_non_expired")
    private boolean credentialsNonExpired;

    @Column(name = "enabled")
    private boolean enabled;

    @Column(name = "email_factor_auth_enabled")
    private boolean emailFactorAuthEnabled;

    @Column(name = "phone_number_factor_auth_enabled")
    private boolean phoneNumberFactorAuthEnabled;

    @Column(name = "authenticator_app_factor_auth_enabled")
    private boolean authenticatorAppFactorAuthEnabled;

    @Column(name = "encrypted_email_confirmation_code_secret")
    private String encryptedEmailConfirmationCodeSecret;

    @Column(name = "encrypted_phone_number_confirmation_code_secret")
    private String encryptedPhoneNumberConfirmationCodeSecret;

    @Column(name = "encrypted_authenticator_app_confirmation_code_secret")
    private String encryptedAuthenticatorAppConfirmationCodeSecret;

    @Column(name = "registration_date", nullable = false)
    private final LocalDateTime registrationDate = LocalDateTime.now();

    @Column(name = "last_login_date", nullable = false)
    @Builder.Default
    private LocalDateTime lastLoginDate = LocalDateTime.now();

    @JsonIgnore
    public Set<CustomerUserAuthority> getAuthoritiesSet() {
        return authorities;
    }

    @JsonProperty("authorities")
    public Set<CustomerUserAuthority> getAuthoritiesAsStrings() {
        return authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = this.authorities.stream()
                    .map(CustomerUserAuthority::name)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

        authorities.addAll(this.roles.stream()
                    .map(CustomerUserRole::name)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList()));
    
        return authorities;
    }

    @Override
    @JsonIgnore
    public String getPassword() {
        return hashPassword;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public boolean isEmailFactorAuthEnabled() {
        return emailFactorAuthEnabled;
    }

    public boolean isPhoneNumberFactorAuthEnabled() {
        return phoneNumberFactorAuthEnabled;
    }

    public boolean isAuthenticatorAppFactorAuthEnabled() {
        return authenticatorAppFactorAuthEnabled;
    }
}
