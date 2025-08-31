package com.marketplace.authentication.configs;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;

@Configuration
public class OtpConfig {

    @Bean
    public TimeBasedOneTimePasswordGenerator totpGenerator() {
        return new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6);
    }
}
