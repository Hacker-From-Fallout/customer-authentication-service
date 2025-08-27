package com.marketplace.authentication.repositories;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.marketplace.authentication.domain.entities.CustomerUser;

@Repository
public interface CustomerUserRepository extends JpaRepository<CustomerUser, Long>, JpaSpecificationExecutor<CustomerUser> { 
    Optional<CustomerUser> findById(Long id);
    Optional<CustomerUser> findByUsername(String username);
    Optional<CustomerUser> findByEmail(String email);
    Optional<CustomerUser> findByPhoneNumber(String phoneNumber);

    @Modifying
    @Query(value = "UPDATE customer_users u SET username = :username WHERE u.id = :id", nativeQuery = true)
    void updateUsername(@Param("id") Long id, @Param("username") String username);

    @Modifying
    @Query(value = "UPDATE customer_users u SET email = :email WHERE u.id = :id", nativeQuery = true)
    void updateEmail(@Param("id") Long id, @Param("email") String email);

    @Modifying
    @Query(value = "UPDATE customer_users u SET phone_number = :phone_number WHERE u.id = :id", nativeQuery = true)
    void updatePhoneNumber(@Param("id") Long id, @Param("phone_number") String phoneNumber);

    @Modifying
    @Query(value = "UPDATE customer_users u SET hash_password = :hash_password WHERE u.id = :id", nativeQuery = true)
    void updateHashPassword(@Param("id") Long id, @Param("hash_password") String hashPassword);

    @Modifying
    @Query(value = "UPDATE customer_users u SET account_non_expired = :account_non_expired WHERE u.id = :id", nativeQuery = true)
    void updateAccountNonExpired(@Param("id") Long id, @Param("account_non_expired") boolean accountNonExpired);

    @Modifying
    @Query(value = "UPDATE customer_users u SET account_non_locked = :account_non_locked WHERE u.id= :id", nativeQuery = true)
    void updateAccountNonLocked(@Param("id") Long id, @Param("account_non_locked") boolean accountNonLocked);

    @Modifying
    @Query(value = "UPDATE customer_users u SET credentials_non_expired = :credentials_non_expired WHERE u.id= :id", nativeQuery = true)
    void updateCredentialsNonExpired(@Param("id") Long id, @Param("credentials_non_expired") boolean credentialsNonExpired);

    @Modifying
    @Query(value = "UPDATE customer_users u SET enabled= :enabled WHERE u.id= :id", nativeQuery = true)
    void updateEnabled(@Param("id") Long id, @Param("enabled") boolean enabled);

    @Modifying
    @Query(value = "UPDATE customer_users u SET email_factor_auth_enabled= :enabled WHERE u.id= :id", nativeQuery = true)
    void updateEmailFactorAuthEnabled(@Param("id") Long id, @Param("enabled") boolean enabled);

    @Modifying
    @Query(value = "UPDATE customer_users u SET phone_number_factor_auth_enabled= :enabled WHERE u.id= :id", nativeQuery = true)
    void updatePhoneNumberFactorAuthEnabled(@Param("id") Long id, @Param("enabled") boolean enabled);

    @Modifying
    @Query(value = "UPDATE customer_users u SET authenticator_app_factor_auth_enabled= :enabled WHERE u.id= :id", nativeQuery = true)
    void updateAuthenticatorAppFactorAuthEnabled(@Param("id") Long id, @Param("enabled") boolean enabled);

    @Modifying
    @Query(value = "UPDATE customer_users u SET last_login_date = :last_login_date WHERE u.id = :id", nativeQuery = true)
    void updateLastLoginDate(@Param("id") Long id, @Param("last_login_date") LocalDateTime lastLoginDate);

    @Modifying
    @Query(value = 
        "INSERT INTO customer_user_authorities (user_id, authorities) VALUES (:user_id, :authority) " +
        "ON CONFLICT (user_id, authorities) DO NOTHING", nativeQuery = true)
    void addAuthority(@Param("user_id") Long userId, @Param("authority") String authority);

    @Modifying
    @Query(value = "DELETE FROM customer_user_authorities WHERE user_id= :user_id AND authorities= :authority", nativeQuery = true)
    void removeAuthority(@Param("user_id") Long userId, @Param("authority") String authority);

    @Modifying
    @Query(value = "DELETE FROM customer_user_authorities WHERE user_id = :user_id", nativeQuery = true)
    void deleteAllAuthorities(@Param("user_id") Long userId);

    @Modifying
    @Query(value = 
        "INSERT INTO customer_user_roles (user_id, roles) VALUES (:user_id, :role) " +
        "ON CONFLICT (user_id, roles) DO NOTHING", nativeQuery = true)
    void addRole(@Param("user_id") Long userId, @Param("role") String role);

    @Modifying
    @Query(value = "DELETE FROM customer_user_roles WHERE user_id= :user_id AND roles= :role", nativeQuery = true)
    void removeRole(@Param("user_id") Long userId, @Param("role") String role);

    @Modifying
    @Query(value = "DELETE FROM customer_user_roles WHERE user_id = :user_id", nativeQuery = true)
    void deleteAllRoles(@Param("user_id") Long userId);

    void deleteById(Long id);

    boolean existsById(Long Id);
    boolean existsByEmail(String email);
    boolean existsByPhoneNumber(String phoneNumber);
    boolean existsByUsername(String username);
}
