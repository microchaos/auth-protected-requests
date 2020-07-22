package dev.jarand.authprotectedrequests.publickey

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Service
import org.springframework.web.client.RestTemplate
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*

@Service
@ConditionalOnProperty(name = ["authentication.mock.enabled"], havingValue = "false", matchIfMissing = true)
class PublicKeyFetcher(@Value("\${authentication.public-key-endpoint}") val publicKeyEndpoint: String,
                       val authApiRestTemplate: RestTemplate) {

    fun fetchPublicKey(): PublicKey {
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
}
