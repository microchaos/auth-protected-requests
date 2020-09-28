package dev.jarand.authprotectedrequests.authapi

import java.security.PublicKey

interface AuthApiClient {
    fun fetchPublicKey(): PublicKey

    fun refreshToken(refreshToken: String): String?
}
