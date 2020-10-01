package dev.jarand.authprotectedrequests.authapi

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Service
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestTemplate
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*

@Service
@ConditionalOnProperty(name = ["authentication.mock.enabled"], havingValue = "false", matchIfMissing = true)
class AuthApiClientImpl(@Value("\${authentication.api.endpoint.public-key}") val publicKeyEndpoint: String,
                        @Value("\${authentication.api.endpoint.refresh-token}") val refreshTokenEndpoint: String,
                        private val authApiRestTemplate: RestTemplate) : AuthApiClient {

    override fun fetchPublicKey(): PublicKey {
        val response = authApiRestTemplate.getForEntity(publicKeyEndpoint, KeyResource::class.java)
        if (!response.statusCode.is2xxSuccessful) {
            throw IllegalStateException("Received invalid status ${response.statusCodeValue} from auth-api")
        }
        if (response.body == null) {
            throw IllegalStateException("Received empty body from auth-api")
        }
        val keyBytes = Base64.getDecoder().decode(response.body!!.key)
        val x509EncodedKeySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(x509EncodedKeySpec)
    }

    override fun refreshToken(refreshToken: String): String? {
        try {
            logger.debug("Sending POST to refresh token")
            val response = authApiRestTemplate.postForObject(refreshTokenEndpoint, RefreshTokenRequest(refreshToken), RefreshTokenResponse::class.java)
            if (response == null) {
                logger.debug("Response from auth-api was null. Returning null.")
                return null
            }
            return response.accessToken
        } catch (ex: HttpClientErrorException) {
            logger.debug("Response from auth-api was ${ex.rawStatusCode}. Returning null.")
            return null
        }
    }

    companion object {
        private val logger = LoggerFactory.getLogger(AuthApiClientImpl::class.java)
    }
}
