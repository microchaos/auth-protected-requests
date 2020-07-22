package dev.jarand.authprotectedrequests.jws

import dev.jarand.authapi.jws.domain.ParseClaimsResult
import dev.jarand.authapi.jws.domain.ParseClaimsResultState
import io.jsonwebtoken.impl.DefaultClaims
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Service

@Service
@ConditionalOnProperty(name = ["authentication.mock.enabled"], havingValue = "true")
class JwsServiceMock(@Value("\${authentication.mock.scope}") val scope: String) : JwsService {

    override fun parseClaims(encodedJws: String): ParseClaimsResult {
        val claims = DefaultClaims()
        claims.subject = "mock"
        claims["scope"] = scope
        println("${claims.subject} ${claims["scope"]}")
        return ParseClaimsResult(ParseClaimsResultState.SUCCESS, claims)
    }
}
