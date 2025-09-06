package com.marketplace.authentication.security;

import java.time.Duration;
import java.util.Optional;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.marketplace.authentication.domain.dto.redis.RegistrationSession;
import com.marketplace.authentication.exception.exceptions.RegistrationSessionNotFound;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class DefaultRegistrationSessionService implements RegistrationSessionService {

    private final RedisTemplate<String, RegistrationSession> jsonRedisTemplate;
    private final Duration timeout = Duration.ofMinutes(5);

    public RegistrationSession getSession(String sessionId) {
        return Optional.ofNullable(jsonRedisTemplate.opsForValue().get(sessionId))
            .orElseThrow(() -> new RegistrationSessionNotFound("Регистрационная сессия не найдена c id: " + sessionId));
    }

    public void saveSession(String sessionId, RegistrationSession session) {
        jsonRedisTemplate.opsForValue().set(sessionId, session, this.timeout);
    }

    public void updateSession(String sessionId, RegistrationSession session) {
        jsonRedisTemplate.opsForValue().set(sessionId, session, this.timeout);
    }

    public void deleteSession(String sessionId) {
        jsonRedisTemplate.delete(sessionId);
    }
}
