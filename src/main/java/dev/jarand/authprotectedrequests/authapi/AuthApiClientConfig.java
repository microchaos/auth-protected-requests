package dev.jarand.authprotectedrequests.authapi;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AuthApiClientConfig {

    @Bean
    @ConditionalOnProperty(name = "authentication.mock.enabled", havingValue = "false", matchIfMissing = true)
    public RestTemplate authApiRestTemplate(@Value("${authentication.api.base-url}") String baseUrl) {
        return new RestTemplateBuilder().rootUri(baseUrl).build();
    }
}
