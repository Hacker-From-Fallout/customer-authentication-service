package com.marketplace.authentication.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

import com.marketplace.authentication.domain.dto.redis.CustomerUserAuthenticationSession;
import com.marketplace.authentication.domain.dto.redis.CustomerUserRegistrationSession;


@Configuration
public class RedisConfig<T> {

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
