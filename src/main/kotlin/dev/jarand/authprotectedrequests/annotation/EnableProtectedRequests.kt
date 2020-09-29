package dev.jarand.authprotectedrequests.annotation

import dev.jarand.authprotectedrequests.WebSecurityConfig
import dev.jarand.authprotectedrequests.authapi.AuthApiClientConfig
import dev.jarand.authprotectedrequests.authapi.AuthApiClientImpl
import dev.jarand.authprotectedrequests.authapi.AuthApiClientMock
import dev.jarand.authprotectedrequests.jws.JwsServiceImpl
import dev.jarand.authprotectedrequests.jws.JwsServiceMock
import org.springframework.context.annotation.Import

@kotlin.annotation.Target(AnnotationTarget.CLASS)
@kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
@Import(value = [WebSecurityConfig::class, JwsServiceImpl::class, JwsServiceMock::class, AuthApiClientImpl::class, AuthApiClientMock::class, AuthApiClientConfig::class])
annotation class EnableProtectedRequests(val protectedRequests: Array<ProtectRequest>, val openRequests: Array<OpenRequest>)
