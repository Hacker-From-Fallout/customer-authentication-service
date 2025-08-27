package com.marketplace.authentication.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.marketplace.authentication.domain.dto.redis.CustomerUserRegistrationSession;

@Configuration
public class RedisConfig {

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);

        StringRedisSerializer stringSerializer = new StringRedisSerializer();

        redisTemplate.setKeySerializer(stringSerializer);
        redisTemplate.setHashKeySerializer(stringSerializer);
        redisTemplate.setHashValueSerializer(stringSerializer);
        redisTemplate.setValueSerializer(stringSerializer);

        redisTemplate.afterPropertiesSet();
        
        return redisTemplate;
    }

    @Bean
    public RedisTemplate<String, CustomerUserRegistrationSession> JsonRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, CustomerUserRegistrationSession> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);

        ObjectMapper mapper = new ObjectMapper();
        Jackson2JsonRedisSerializer<CustomerUserRegistrationSession> serializer = 
            new Jackson2JsonRedisSerializer<>(mapper, CustomerUserRegistrationSession.class);

        redisTemplate.setValueSerializer(serializer);

        return redisTemplate;
    }
}
