package com.marketplace.authentication.configs;

import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.LongSerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class KafkaProducerConfig {

    private final KafkaProperties kafkaProperties;

    @Bean
    public ProducerFactory<String, Long> longProducerFactory() {
        Map<String, Object> configProps = new HashMap<>();

        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaProperties.getBootstrapServers());
        configProps.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 30000);
        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, LongSerializer.class);
        configProps.put(ProducerConfig.RETRIES_CONFIG, 10); 
        configProps.put(ProducerConfig.ACKS_CONFIG, "all"); 
        configProps.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true); 
        configProps.put(ProducerConfig.LINGER_MS_CONFIG, 5); 
        configProps.put(ProducerConfig.BATCH_SIZE_CONFIG, 32 * 1024); 
        configProps.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "snappy"); 
        configProps.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 30000);
        configProps.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 60000);

        return new DefaultKafkaProducerFactory<>(configProps);
    }

    @Bean
    public KafkaTemplate<String, Long> longKafkaTemplate() {
        return new KafkaTemplate<>(longProducerFactory());
    }

    @Bean
    public ProducerFactory<String, Object> jsonProducerFactory() {
        Map<String, Object> configProps = new HashMap<>();
        
        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaProperties.getBootstrapServers());
        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        configProps.put(ProducerConfig.RETRIES_CONFIG, 10); 
        configProps.put(ProducerConfig.ACKS_CONFIG, "all"); 
        configProps.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true); 
        configProps.put(ProducerConfig.LINGER_MS_CONFIG, 5); 
        configProps.put(ProducerConfig.BATCH_SIZE_CONFIG, 32 * 1024); 
        configProps.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "snappy"); 
        configProps.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 30000);
        configProps.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 60000);

        return new DefaultKafkaProducerFactory<>(configProps);
    }

    @Bean
    public KafkaTemplate<String, Object> jsonKafkaTemplate() {
        return new KafkaTemplate<>(jsonProducerFactory());
    }
}
