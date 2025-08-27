package com.marketplace.authentication.producers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import com.marketplace.authentication.domain.dto.kafka.CustomerProfileCreateDto;
import com.marketplace.authentication.domain.dto.kafka.EmailUpdateDto;
import com.marketplace.authentication.domain.dto.kafka.PhoneNumberUpdateDto;
import com.marketplace.authentication.domain.dto.kafka.UsernameUpdateDto;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class CustomerUserProducer {

    private final KafkaTemplate<String, Object> jsonKafkaTemplate;
    private final KafkaTemplate<String, Long> longKafkaTemplate;

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

    public void createProfile(CustomerProfileCreateDto dto) {
        jsonKafkaTemplate.send(CREATE_PROFILE_CUSTOMER_TOPIC, dto);
    }

    public void updateUsername(Long id, String username) {
        UsernameUpdateDto dto = new UsernameUpdateDto(id, username);
        jsonKafkaTemplate.send(UPDATE_USERNAME_CUSTOMER_TOPIC, dto);
    }

    public void updateEmail(Long id, String email) {
        EmailUpdateDto dto = new EmailUpdateDto(id, email);
        jsonKafkaTemplate.send(UPDATE_EMAIL_CUSTOMER_TOPIC, dto);
    }

    public void updatePhoneNumber(Long id, String phoneNumber) {
        PhoneNumberUpdateDto dto = new PhoneNumberUpdateDto(id, phoneNumber);
        jsonKafkaTemplate.send(UPDATE_PHONE_NUMBER_CUSTOMER_TOPIC, dto);
    }

    public void deleteProfile(Long id) {
        longKafkaTemplate.send(DELETE_PROFILE_CUSTOMER_TOPIC, id);
    }
}
