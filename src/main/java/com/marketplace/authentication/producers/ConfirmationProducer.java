package com.marketplace.authentication.producers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import com.marketplace.authentication.domain.dto.kafka.EmailConfirmationCodeDto;
import com.marketplace.authentication.domain.dto.kafka.PhoneNumberConfirmationCodeDto;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class ConfirmationProducer {

    private final KafkaTemplate<String, Object> jsonKafkaTemplate;

    @Value("${spring.kafka.topics.email-confirmation}")
    private String EMAIL_CONFIRMATION_TOPIC;

    @Value("${spring.kafka.topics.phone-number-confirmation}")
    private String PHONE_NUMBER_CONFIRMATION_TOPIC;

    public void emailConfirmation(EmailConfirmationCodeDto dto) {
        jsonKafkaTemplate.send(EMAIL_CONFIRMATION_TOPIC, dto);
    }

    public void phoneNumberConfirmation(PhoneNumberConfirmationCodeDto dto) {
        jsonKafkaTemplate.send(PHONE_NUMBER_CONFIRMATION_TOPIC, dto);
    }
}
