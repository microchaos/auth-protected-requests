package dev.jarand.authapi.jws.domain

enum class ParseClaimsResultState {
    EXPIRED, INVALID_FORMAT, INVALID_SIGNATURE, SUCCESS
}
