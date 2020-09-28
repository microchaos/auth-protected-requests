package dev.jarand.authprotectedrequests.jws

import dev.jarand.authprotectedrequests.authapi.AuthApiClient
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.security.SignatureException
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Service
import java.security.PublicKey

@Service
@ConditionalOnProperty(name = ["authentication.mock.enabled"], havingValue = "false", matchIfMissing = true)
class JwsServiceImpl(private val authApiClient: AuthApiClient) : JwsService {

    private var publicKey: PublicKey? = null

    override fun parseClaims(encodedJws: String): ParseClaimsResult {
        if (publicKey == null) {
            publicKey = authApiClient.fetchPublicKey()
        }
        val result = attemptParsing(encodedJws)
        if (result.state == ParseClaimsResultState.INVALID_SIGNATURE) {
            publicKey = authApiClient.fetchPublicKey()
        }
        return attemptParsing(encodedJws)
    }

    private fun attemptParsing(encodedJws: String): ParseClaimsResult {
        return try {
            val jws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(encodedJws)
            ParseClaimsResult(ParseClaimsResultState.SUCCESS, jws.body)
        } catch (ex: Exception) {
            when (ex) {
                is ExpiredJwtException -> ParseClaimsResult(ParseClaimsResultState.EXPIRED, null)
                is SignatureException -> ParseClaimsResult(ParseClaimsResultState.INVALID_SIGNATURE, null)
                is UnsupportedJwtException,
                is MalformedJwtException,
                is IllegalArgumentException -> ParseClaimsResult(ParseClaimsResultState.INVALID_FORMAT, null)
                else -> throw IllegalStateException("Unhandled exception", ex)
            }
        }
    }
}
