package com.marketplace.authentication.security;

import java.time.Duration;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class DefaultBlacklistTokenService implements BlacklistTokenService {

    private final RedisTemplate<String, String> stringRedisTemplate;
    private final Duration timeout = Duration.ofDays(1);

    public String getToken(String tokenId) {
        return stringRedisTemplate.opsForValue().get(tokenId);
    }

    public void saveToken(String tokenId) {
        stringRedisTemplate.opsForValue().set(tokenId, "", this.timeout);
    }

    public void updateToken(String tokenId) {
        stringRedisTemplate.opsForValue().set(tokenId, "", this.timeout);
    }

    public void deleteToken(String tokenId) {
        stringRedisTemplate.delete(tokenId);
    }
}
