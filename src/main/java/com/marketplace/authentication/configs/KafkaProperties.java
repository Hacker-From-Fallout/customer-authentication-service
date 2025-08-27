package com.marketplace.authentication.configs;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "spring.kafka")
public class KafkaProperties {

    private List<String> bootstrapServers;
    
    public List<String> getBootstrapServers() {
        return bootstrapServers;
    }

    public void setBootstrapServers(List<String> bootstrapServers) {
        this.bootstrapServers = bootstrapServers;
    }

    public Map<String, Object> getProperties() {
        Map<String, Object> props = new HashMap<>();

        if (bootstrapServers != null && !bootstrapServers.isEmpty()) {
            String servers = String.join(",", bootstrapServers);
            props.put("bootstrap.servers", servers);
        }

        return props;
    }
}
