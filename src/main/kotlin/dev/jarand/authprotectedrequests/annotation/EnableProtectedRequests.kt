package dev.jarand.authprotectedrequests.annotation

import dev.jarand.authprotectedrequests.WebSecurityConfig
import dev.jarand.authprotectedrequests.jws.JwsServiceImpl
import dev.jarand.authprotectedrequests.jws.JwsServiceMock
import dev.jarand.authprotectedrequests.publickey.PublicKeyFetcher
import dev.jarand.authprotectedrequests.publickey.PublicKeyFetcherConfig
import org.springframework.context.annotation.Import

@kotlin.annotation.Target(AnnotationTarget.CLASS)
@kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
@Import(value = [WebSecurityConfig::class, JwsServiceImpl::class, JwsServiceMock::class, PublicKeyFetcher::class, PublicKeyFetcherConfig::class])
annotation class EnableProtectedRequests(val protectedRequests: Array<ProtectRequest>, val openRequests: Array<OpenRequest>)
