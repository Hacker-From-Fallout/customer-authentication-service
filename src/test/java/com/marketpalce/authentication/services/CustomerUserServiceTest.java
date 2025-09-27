package com.marketpalce.authentication.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.marketplace.authentication.domain.authorities.CustomerUserAuthority;
import com.marketplace.authentication.domain.authorities.CustomerUserRole;
import com.marketplace.authentication.domain.dto.kafka.CustomerProfileCreateDto;
import com.marketplace.authentication.domain.dto.request.CustomerUserCreateDto;
import com.marketplace.authentication.domain.entities.CustomerUser;
import com.marketplace.authentication.exception.exceptions.AlreadyExistsException;
import com.marketplace.authentication.exception.exceptions.UserNotFoundException;
import com.marketplace.authentication.producers.CustomerProfileProducer;
import com.marketplace.authentication.repositories.CustomerUserRepository;
import com.marketplace.authentication.security.BlacklistTokenService;
import com.marketplace.authentication.services.DefaultCustomerUserService;

@ExtendWith(MockitoExtension.class)
public class CustomerUserServiceTest {

    @Mock
    private CustomerUserRepository customerUserRepository;

    @Mock
    private CustomerProfileProducer customerProfileProducer;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private BlacklistTokenService blacklistTokenService;

    @Spy
    @InjectMocks
    private DefaultCustomerUserService customerUserService;

    @Test
    void findById_UserExists_ShouldReturnUser() {
        CustomerUser customerUser = createTestCustomerUser();
        when(customerUserRepository.findById(1L)).thenReturn(Optional.of(customerUser));

        CustomerUser result = customerUserService.findById(1L);

        assertNotNull(result);
        assertEquals(customerUser.getUsername(), result.getUsername());
        verify(customerUserRepository, times(1)).findById(1L);
    }

    @Test
    void findById_UserNotFound_ShouldThrowException() {
        when(customerUserRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> customerUserService.findById(1L));
        verify(customerUserRepository, times(1)).findById(1L); 
    }

    @Test
    void findByUsername_UserExists_ShouldReturnUser() {
        CustomerUser customerUser = createTestCustomerUser();
        when(customerUserRepository.findByUsername(customerUser.getUsername())).thenReturn(Optional.of(customerUser));

        CustomerUser result = customerUserService.findByUsername(customerUser.getUsername());

        assertNotNull(result);
        assertEquals(customerUser.getUsername(), result.getUsername());
        verify(customerUserRepository, times(1)).findByUsername(customerUser.getUsername());
    }

    @Test
    void findByUsername_UserNotFound_ShouldThrowException() {
        String username = "TestUsername";
        when(customerUserRepository.findByUsername(username)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> customerUserService.findByUsername(username));
        verify(customerUserRepository, times(1)).findByUsername(username);
    }

    @Test
    void findByEmail_UserExists_ShouldReturnUser() {
        CustomerUser customerUser = createTestCustomerUser();
        when(customerUserRepository.findByEmail(customerUser.getEmail())).thenReturn(Optional.of(customerUser));

        CustomerUser result = customerUserService.findByEmail(customerUser.getEmail());

        assertNotNull(result);
        assertEquals(customerUser.getEmail(), result.getEmail());
        verify(customerUserRepository, times(1)).findByEmail(customerUser.getEmail());
    }

    @Test
    void findByEmail_UserNotFound_ShouldThrowException() {
        String email = "test@test.test";
        when(customerUserRepository.findByEmail(email)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> customerUserService.findByEmail(email));
        verify(customerUserRepository, times(1)).findByEmail(email);
    }

    @Test
    void findByPhoneNumber_UserExists_ShouldReturnUser() {
        CustomerUser customerUser = createTestCustomerUser();
        when(customerUserRepository.findByPhoneNumber(customerUser.getPhoneNumber())).thenReturn(Optional.of(customerUser));

        CustomerUser result = customerUserService.findByPhoneNumber(customerUser.getPhoneNumber());

        assertNotNull(result);
        assertEquals(customerUser.getPhoneNumber(), result.getPhoneNumber());
        verify(customerUserRepository, times(1)).findByPhoneNumber(customerUser.getPhoneNumber());
    }

    @Test
    void findByPhoneNumber_UserNotFound_ShouldThrowException() {
        String phoneNumber = "+1234567890";
        when(customerUserRepository.findByPhoneNumber(phoneNumber)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> customerUserService.findByPhoneNumber(phoneNumber));
        verify(customerUserRepository, times(1)).findByPhoneNumber(phoneNumber);
    }

    @Test
    void createUser_ValidDto_ShouldCreateAndReturnUser() {
        CustomerUserCreateDto dto = createTestCustomerUserCreateDto();
        CustomerUser savedCustomerUser = createTestCustomerUser();
        when(passwordEncoder.encode(anyString())).thenReturn("encoded_password123456789@@@");
        when(customerUserRepository.save(any(CustomerUser.class))).thenReturn(savedCustomerUser);
        doNothing().when(customerProfileProducer).createProfile(any(CustomerProfileCreateDto.class));

        CustomerUser result = customerUserService.createUser(dto);

        assertNotNull(result);
        assertEquals(1L, result.getId());
        assertEquals(dto.username(), result.getUsername());

        ArgumentCaptor<CustomerUser> userArgumentCaptor = ArgumentCaptor.forClass(CustomerUser.class);
        verify(customerUserRepository).save(userArgumentCaptor.capture());
        CustomerUser capturedUser = userArgumentCaptor.getValue();
        assertEquals(dto.username(), capturedUser.getUsername());
        assertEquals(savedCustomerUser.getHashPassword(), capturedUser.getHashPassword());

        ArgumentCaptor<CustomerProfileCreateDto> profileArgumentCaptor = ArgumentCaptor.forClass(CustomerProfileCreateDto.class);
        verify(customerProfileProducer).createProfile(profileArgumentCaptor.capture());
        CustomerProfileCreateDto profileDto = profileArgumentCaptor.getValue();
        assertEquals(savedCustomerUser.getId(), profileDto.id());
        assertEquals(dto.firstName(), profileDto.firstName());
    }

    @Test
    void createUser_WhenUsernameExists_ShouldThrowAlreadyExistsException() {
        CustomerUserCreateDto dto = createTestCustomerUserCreateDto();
        String username = dto.username();
        when(customerUserRepository.existsByUsername(username)).thenReturn(true);

        assertThrows(AlreadyExistsException.class, () -> customerUserService.createUser(dto));
        verify(customerUserRepository, times(1)).existsByUsername(username);
    }

    @Test
    void createUser_WhenEmailExists_ShouldThrowAlreadyExistsException() {
        CustomerUserCreateDto dto = createTestCustomerUserCreateDto();
        String email = dto.email();
        when(customerUserRepository.existsByEmail(email)).thenReturn(true);

        assertThrows(AlreadyExistsException.class, () -> customerUserService.createUser(dto));
        verify(customerUserRepository, times(1)).existsByEmail(email);
    }

    @Test
    void createUser_WhenPhoneNumberExists_ShouldThrowAlreadyExistsException() {
        CustomerUserCreateDto dto = createTestCustomerUserCreateDto();
        String phoneNumber = dto.phoneNumber();
        when(customerUserRepository.existsByPhoneNumber(phoneNumber)).thenReturn(true);

        assertThrows(AlreadyExistsException.class, () -> customerUserService.createUser(dto));
        verify(customerUserRepository, times(1)).existsByPhoneNumber(phoneNumber);
    }

    @Test
    void updateUsername_ValidUsername_ShouldUpdateUsername() {
        Long userId = 1L;
        String newUsername = "newUser";  
        when(customerUserRepository.existsByUsername(newUsername)).thenReturn(false);
        
        customerUserService.updateUsername(userId, newUsername);

        verify(customerUserRepository).updateUsername(userId, newUsername);
        verify(customerProfileProducer).updateUsername(userId, newUsername);
    }

    @Test
    void updateUsername_WhenUsernameExists_ShouldThrowAlreadyExistsException() {
        Long userId = 1L;
        String newUsername = "TestUsername";  
        when(customerUserRepository.existsByUsername(newUsername)).thenReturn(true);
        
        assertThrows(AlreadyExistsException.class, () -> customerUserService.updateUsername(userId, newUsername));

        verify(customerUserRepository, times(1)).existsByUsername(newUsername);
        verify(customerUserRepository, never()).updateUsername(anyLong(), anyString());
        verify(customerProfileProducer, never()).updateUsername(anyLong(), anyString());
    }

    @Test
    void updateEmail_ValidEmail_ShouldUpdateEmail() {
        Long userId = 1L;
        String newEmail = "newemail@example.com";
        when(customerUserRepository.existsByEmail(newEmail)).thenReturn(false);

        customerUserService.updateEmail(userId, newEmail);

        verify(customerUserRepository).updateEmail(userId, newEmail);
        verify(customerProfileProducer).updateEmail(userId, newEmail);
    }

    @Test
    void updateEmail_WhenEmailExists_ShouldThrowAlreadyExistsException() {
        Long userId = 1L;
        String newEmail = "existingemail@example.com";
        when(customerUserRepository.existsByEmail(newEmail)).thenReturn(true);

        assertThrows(AlreadyExistsException.class, () -> customerUserService.updateEmail(userId, newEmail));

        verify(customerUserRepository, times(1)).existsByEmail(newEmail);
        verify(customerUserRepository, never()).updateEmail(anyLong(), anyString());
        verify(customerProfileProducer, never()).updateEmail(anyLong(), anyString());
    }

    @Test
    void updatePhoneNumber_ValidPhoneNumber_ShouldUpdatePhoneNumber() {
        Long userId = 1L;
        String newPhoneNumber = "+71234567890";
        when(customerUserRepository.existsByPhoneNumber(newPhoneNumber)).thenReturn(false);

        customerUserService.updatePhoneNumber(userId, newPhoneNumber);

        verify(customerUserRepository).updatePhoneNumber(userId, newPhoneNumber);
        verify(customerProfileProducer).updatePhoneNumber(userId, newPhoneNumber);
    }

    @Test
    void updatePhoneNumber_WhenPhoneNumberExists_ShouldThrowAlreadyExistsException() {
        Long userId = 1L;
        String newPhoneNumber = "+79998887766";
        when(customerUserRepository.existsByPhoneNumber(newPhoneNumber)).thenReturn(true);

        assertThrows(AlreadyExistsException.class, () -> customerUserService.updatePhoneNumber(userId, newPhoneNumber));

        verify(customerUserRepository, times(1)).existsByPhoneNumber(newPhoneNumber);
        verify(customerUserRepository, never()).updatePhoneNumber(anyLong(), anyString());
        verify(customerProfileProducer, never()).updatePhoneNumber(anyLong(), anyString());
    }

    @Test
    void updateHashPassword_ShouldUpdateHashPassword() {
        Long userId = 1L;
        String newHashPassword = "hashedPassword123";

        customerUserService.updateHashPassword(userId, newHashPassword);

        verify(customerUserRepository).updateHashPassword(userId, newHashPassword);
    }

    @Test
    void updateRoles_ShouldUpdateRoles() {
        Long userId = 1L;
        EnumSet<CustomerUserRole> roles = EnumSet.copyOf(getAllRoles());
        doNothing().when(customerUserRepository).deleteAllRoles(any(Long.class));

        customerUserService.updateRoles(userId, roles);

        for (CustomerUserRole role : roles) {
            verify(customerUserRepository, times(1)).addRole(userId, role.name());
        }
    }

    private CustomerUser createTestCustomerUser() {
        return CustomerUser.builder()
            .id(1L)
            .username("TestUsername")
            .email("test@test.test")
            .phoneNumber("+1234567890")
            .hashPassword("encoded_password123456789@@@")
            .roles(getAllRoles())
            .authorities(getAllAuthority())
            .accountNonExpired(true)
            .accountNonLocked(true)
            .credentialsNonExpired(true)
            .enabled(true)
            .emailFactorAuthEnabled(false)
            .phoneNumberFactorAuthEnabled(false)
            .authenticatorAppFactorAuthEnabled(false)
            .tokenId("2f934tfg230tfgg247grbf")
            .build();
    }

    private CustomerUserCreateDto createTestCustomerUserCreateDto() {
        return new CustomerUserCreateDto(
            "TestFirstName", 
            "TestLastname", 
            "TestUsername", 
            "test@test.test", 
            "+1234567890", 
            "password123456789@@@",
            EnumSet.copyOf(getAllRoles()), 
            EnumSet.copyOf(getAllAuthority()), 
            true, 
            true, 
            true, 
            true, 
            false, 
            false, 
            false
        );
    }

    private Set<CustomerUserRole> getAllRoles() {
        return EnumSet.allOf(CustomerUserRole.class);
    }

    private Set<CustomerUserAuthority> getAllAuthority() {
        return EnumSet.allOf(CustomerUserAuthority.class);
    }
}
