package com.marketplace.authentication.configs;

import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;

import com.fasterxml.jackson.databind.ObjectMapper;

public class RedisTemplateBuilder {

    public static <T> RedisTemplate<String, T> buildJsonRedisTemplate(RedisConnectionFactory redisConnectionFactory, Class<T> valueType) {
        RedisTemplate<String, T> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);

        ObjectMapper mapper = new ObjectMapper();
        Jackson2JsonRedisSerializer<T> serializer = 
            new Jackson2JsonRedisSerializer<>(mapper, valueType);

        redisTemplate.setKeySerializer(redisTemplate.getStringSerializer());
        redisTemplate.setValueSerializer(serializer);

        return redisTemplate;
    }
}
