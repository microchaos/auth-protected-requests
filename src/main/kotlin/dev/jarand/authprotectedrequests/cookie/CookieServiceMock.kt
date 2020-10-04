package dev.jarand.authprotectedrequests.cookie

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Service
import javax.servlet.http.Cookie

@Service
@ConditionalOnProperty(name = ["authentication.mock.enabled"], havingValue = "true")
class CookieServiceMock : CookieService {

    override fun createAccessTokenCookie(accessToken: String): Cookie {
        throw IllegalStateException("Not implemented")
    }
}
