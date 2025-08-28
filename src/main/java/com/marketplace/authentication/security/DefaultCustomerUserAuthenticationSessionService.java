package com.marketplace.authentication.security;

import java.time.Duration;
import java.util.Optional;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.marketplace.authentication.domain.dto.redis.CustomerUserAuthenticationSession;
import com.marketplace.authentication.exception.exceptions.RegistrationSessionNotFound;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class DefaultCustomerUserAuthenticationSessionService implements CustomerUserAuthenticationSessionService {

    private final RedisTemplate<String, CustomerUserAuthenticationSession> jsonRedisTemplate;

    public CustomerUserAuthenticationSession getSession(String sessionId) {
        return Optional.ofNullable(jsonRedisTemplate.opsForValue().get(sessionId))
            .orElseThrow(() -> new RegistrationSessionNotFound("Аутентификационная сессия не найдена c id: " + sessionId));
    }

    public void saveSession(String sessionId, CustomerUserAuthenticationSession session, Duration timeout) {
        jsonRedisTemplate.opsForValue().set(sessionId, session, timeout);
    }

    public void updateSession(String sessionId, CustomerUserAuthenticationSession session, Duration timeout) {
        jsonRedisTemplate.opsForValue().set(sessionId, session, timeout);
    }

    public void deleteSession(String sessionId) {
        jsonRedisTemplate.delete(sessionId);
    }
}
