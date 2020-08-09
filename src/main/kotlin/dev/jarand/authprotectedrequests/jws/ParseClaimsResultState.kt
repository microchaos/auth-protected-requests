package dev.jarand.authprotectedrequests.jws

enum class ParseClaimsResultState {
    EXPIRED, INVALID_FORMAT, INVALID_SIGNATURE, SUCCESS
}
