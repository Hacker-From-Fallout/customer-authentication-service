package com.marketplace.authentication.configs;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class KafkaCustomerTopicConfig {

    @Value("${spring.kafka.topics.customer.create-profile}")
    private String CREATE_PROFILE_CUSTOMER_TOPIC;

    @Value("${spring.kafka.topics.customer.update-username}")
    private String UPDATE_USERNAME_CUSTOMER_TOPIC;

    @Value("${spring.kafka.topics.customer.update-email}")
    private String UPDATE_EMAIL_CUSTOMER_TOPIC;

    @Value("${spring.kafka.topics.customer.update-phone-number}")
    private String UPDATE_PHONE_NUMBER_CUSTOMER_TOPIC;

    @Value("${spring.kafka.topics.customer.delete-profile}")
    private String DELETE_PROFILE_CUSTOMER_TOPIC;

    @Bean
    public NewTopic createCustomerProfileTopic() {
        return TopicBuilder.name(CREATE_PROFILE_CUSTOMER_TOPIC)
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
    public NewTopic updateCustomerUsernameTopic() {
        return TopicBuilder.name(UPDATE_USERNAME_CUSTOMER_TOPIC)
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
    public NewTopic updateCustomerEmailTopic() {
        return TopicBuilder.name(UPDATE_EMAIL_CUSTOMER_TOPIC)
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
    public NewTopic updateCustomerPhoneTopic() {
        return TopicBuilder.name(UPDATE_PHONE_NUMBER_CUSTOMER_TOPIC)
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
    public NewTopic deleteCustomerProfileTopic() {
        return TopicBuilder.name(DELETE_PROFILE_CUSTOMER_TOPIC)
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
