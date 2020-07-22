package dev.jarand.authapi.jws.domain

import io.jsonwebtoken.Claims

data class ParseClaimsResult(val state: ParseClaimsResultState, val claims: Claims?)
