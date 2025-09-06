package com.marketplace.authentication.security;

import java.time.Duration;
import java.util.Optional;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.marketplace.authentication.domain.dto.redis.AuthenticationSession;
import com.marketplace.authentication.exception.exceptions.RegistrationSessionNotFound;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class DefaultAuthenticationSessionService implements AuthenticationSessionService {

    private final RedisTemplate<String, AuthenticationSession> jsonRedisTemplate;
    private final Duration timeout = Duration.ofMinutes(5);

    public AuthenticationSession getSession(String sessionId) {
        return Optional.ofNullable(jsonRedisTemplate.opsForValue().get(sessionId))
            .orElseThrow(() -> new RegistrationSessionNotFound("Аутентификационная сессия не найдена c id: " + sessionId));
    }

    public void saveSession(String sessionId, AuthenticationSession session) {
        jsonRedisTemplate.opsForValue().set(sessionId, session, this.timeout);
    }

    public void updateSession(String sessionId, AuthenticationSession session) {
        jsonRedisTemplate.opsForValue().set(sessionId, session, this.timeout);
    }

    public void deleteSession(String sessionId) {
        jsonRedisTemplate.delete(sessionId);
    }
}
