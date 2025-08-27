package com.marketplace.authentication.security;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.marketplace.authentication.domain.dto.redis.CustomerUserRegistrationSession;
import com.marketplace.authentication.exception.exceptions.RegistrationSessionNotFound;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class DefaultCustomerUserRegistrationSessionService implements CustomerUserRegistrationSessionService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisTemplate<String, CustomerUserRegistrationSession> jsonRedisTemplate;

    public CustomerUserRegistrationSession getSession(String sessionId) {
        return Optional.ofNullable(jsonRedisTemplate.opsForValue().get(sessionId))
            .orElseThrow(() -> new RegistrationSessionNotFound("Регистрационная сессия не найдена c id: " + sessionId));
    }

    public CustomerUserRegistrationSession getSessionHash(String sessionId) {
        Map<Object, Object> hashMap = redisTemplate.opsForHash().entries(sessionId);
        if (hashMap == null || hashMap.isEmpty()) {
            return null; 
        }

        Map<String, Object> stringObjectMap = hashMap.entrySet().stream()
            .collect(Collectors.toMap(
                e -> e.getKey().toString(),
                Map.Entry::getValue
            ));

        ObjectMapper mapper = new ObjectMapper();
        CustomerUserRegistrationSession session = mapper.convertValue(stringObjectMap, CustomerUserRegistrationSession.class);
        return session;
    }

    // public Map<Object, Object> getSessionHash(String sessionId) {
    //     return redisTemplate.opsForHash().entries(sessionId);
    // }

    public Object getFieldFromSession(String sessionId, String fieldName) {
        return redisTemplate.opsForHash().get(sessionId, fieldName);
    }

    public void saveSession(String sessionId, CustomerUserRegistrationSession session, Duration timeout) {
        jsonRedisTemplate.opsForValue().set(sessionId, session, timeout);
    }

    public void saveSessionAsHash(String sessionId, CustomerUserRegistrationSession session, Duration timeout) {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> hashMap = mapper.convertValue(session, new TypeReference<Map<String, Object>>() {});
        redisTemplate.opsForHash().putAll(sessionId, hashMap);
        redisTemplate.expire(sessionId, timeout);
    }

    public void updateSession(String sessionId, CustomerUserRegistrationSession session, Duration timeout) {
        jsonRedisTemplate.opsForValue().set(sessionId, session, timeout);
    }

    public void updateFieldInSession(String sessionId, String fieldName, Object newValue) {
        redisTemplate.opsForHash().put(sessionId, fieldName, newValue);
    }

    public void deleteSession(String sessionId) {
        redisTemplate.delete(sessionId);
        jsonRedisTemplate.delete(sessionId);
    }
}
