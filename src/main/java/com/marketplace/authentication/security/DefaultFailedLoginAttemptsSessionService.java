package com.marketplace.authentication.security;

import java.time.Duration;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.marketplace.authentication.domain.dto.redis.FailedLoginAttemptsSession;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class DefaultFailedLoginAttemptsSessionService implements FailedLoginAttemptsSessionService {

    private final RedisTemplate<String, FailedLoginAttemptsSession> jsonRedisTemplate;

    public FailedLoginAttemptsSession getSession(String sessionId) {
        return jsonRedisTemplate.opsForValue().get(sessionId);
    }

    public void saveSession(String sessionId, FailedLoginAttemptsSession session, Duration timeout) {
        jsonRedisTemplate.opsForValue().set(sessionId, session, timeout);
    }

    public void updateSession(String sessionId, FailedLoginAttemptsSession session, Duration timeout) {
        jsonRedisTemplate.opsForValue().set(sessionId, session, timeout);
    }

    public void deleteSession(String sessionId) {
        jsonRedisTemplate.delete(sessionId);
    }
}
