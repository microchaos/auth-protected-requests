package dev.jarand.authprotectedrequests.publickey

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.client.RestTemplate

@Configuration
class PublicKeyFetcherConfig {

    @Bean
    @ConditionalOnProperty(name = ["authentication.mock.enabled"], havingValue = "false", matchIfMissing = true)
    fun authApiRestTemplate(@Value("\${auth-api.base-url}") baseUrl: String): RestTemplate {
        return RestTemplateBuilder().rootUri(baseUrl).build()
    }
}
