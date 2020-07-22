package dev.jarand.authprotectedrequests.jws

import dev.jarand.authapi.jws.domain.ParseClaimsResult

interface JwsService {
    fun parseClaims(encodedJws: String): ParseClaimsResult
}
