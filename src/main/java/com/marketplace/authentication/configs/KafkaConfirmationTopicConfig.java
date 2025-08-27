package com.marketplace.authentication.configs;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class KafkaConfirmationTopicConfig {

    @Value("${spring.kafka.topics.email-confirmation}")
    private String EMAIL_CONFIRMATION_TOPIC;

    @Value("${spring.kafka.topics.phone-number-confirmation}")
    private String PHONE_NUMBER_CONFIRMATION_TOPIC;

    @Bean
    public NewTopic createEmailConfirmationTopic() {
        return TopicBuilder.name(EMAIL_CONFIRMATION_TOPIC)
            .partitions(3)
            .replicas((short) 3)       
            .config("retention.ms", String.valueOf(7 * 24 * 60 * 60 * 1000L)) 
            .config("retention.bytes", "1073741824") 
            .config("segment.bytes", "1073741824") 
            .config("segment.ms", "604800000")
            .config("cleanup.policy", "delete")
            .config("min.insync.replicas", "1")
            .build();
    }

    @Bean
    public NewTopic createPhoneNumberConfirmationTopic() {
        return TopicBuilder.name(PHONE_NUMBER_CONFIRMATION_TOPIC)
            .partitions(3)
            .replicas((short) 3)       
            .config("retention.ms", String.valueOf(7 * 24 * 60 * 60 * 1000L)) 
            .config("retention.bytes", "1073741824") 
            .config("segment.bytes", "1073741824") 
            .config("segment.ms", "604800000")
            .config("cleanup.policy", "delete")
            .config("min.insync.replicas", "1")
            .build();
    }
}
