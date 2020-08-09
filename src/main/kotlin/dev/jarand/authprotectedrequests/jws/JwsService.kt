package dev.jarand.authprotectedrequests.jws

interface JwsService {
    fun parseClaims(encodedJws: String): ParseClaimsResult
}
