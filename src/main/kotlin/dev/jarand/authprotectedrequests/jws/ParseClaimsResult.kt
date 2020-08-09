package dev.jarand.authprotectedrequests.jws

import io.jsonwebtoken.Claims

data class ParseClaimsResult(val state: ParseClaimsResultState, val claims: Claims?)
