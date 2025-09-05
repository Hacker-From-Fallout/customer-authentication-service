package com.marketplace.authentication.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import com.marketplace.authentication.domain.dto.redis.CustomerUserAuthenticationSession;
import com.marketplace.authentication.domain.dto.redis.CustomerUserRegistrationSession;
import com.marketplace.authentication.domain.dto.redis.FailedLoginAttemptsSession;

@Configuration
public class RedisConfig<T> {

    @Bean
    public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();

        redisTemplate.setConnectionFactory(redisConnectionFactory);

        StringRedisSerializer stringSerializer = new StringRedisSerializer();

        redisTemplate.setKeySerializer(stringSerializer);
        redisTemplate.setValueSerializer(stringSerializer);

        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }

    @Bean
    public RedisTemplate<String, FailedLoginAttemptsSession> failedLoginAttemptsSessionRedisTemplate(
        RedisConnectionFactory redisConnectionFactory) 
    {
        return RedisTemplateBuilder.buildJsonRedisTemplate(redisConnectionFactory, 
            FailedLoginAttemptsSession.class);
    }

    @Bean
    public RedisTemplate<String, CustomerUserRegistrationSession> customerUserRegistrationSessionRedisTemplate(
        RedisConnectionFactory redisConnectionFactory) 
    {
        return RedisTemplateBuilder.buildJsonRedisTemplate(redisConnectionFactory, 
            CustomerUserRegistrationSession.class);
    }

    @Bean
    public RedisTemplate<String, CustomerUserAuthenticationSession> customerUserAuthenticationSessionRedisTemplate(
        RedisConnectionFactory redisConnectionFactory) 
    {
        return RedisTemplateBuilder.buildJsonRedisTemplate(redisConnectionFactory, 
            CustomerUserAuthenticationSession.class);
    }
}

