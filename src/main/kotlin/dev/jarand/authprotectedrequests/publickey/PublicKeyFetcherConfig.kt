package dev.jarand.authprotectedrequests.publickey

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.client.RestTemplate

@Configuration
open class PublicKeyFetcherConfig {

    @Bean
    @ConditionalOnProperty(name = ["authentication.mock.enabled"], havingValue = "false", matchIfMissing = true)
    open fun authApiRestTemplate(): RestTemplate {
        return RestTemplateBuilder().build()
    }
}
