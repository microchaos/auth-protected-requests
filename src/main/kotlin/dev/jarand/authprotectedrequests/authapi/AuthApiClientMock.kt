package dev.jarand.authprotectedrequests.authapi

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Service
import java.security.PublicKey

@Service
@ConditionalOnProperty(name = ["authentication.mock.enabled"], havingValue = "true")
class AuthApiClientMock : AuthApiClient {

    override fun fetchPublicKey(): PublicKey {
        throw IllegalStateException("Not implemented")
    }

    override fun refreshToken(refreshToken: String): String? {
        throw IllegalStateException("Not implemented")
    }
}
