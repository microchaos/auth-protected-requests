package dev.jarand.authprotectedrequests.annotation

import org.springframework.http.HttpMethod

@kotlin.annotation.Target(AnnotationTarget.TYPE)
@kotlin.annotation.Retention(AnnotationRetention.RUNTIME)
annotation class OpenRequest(val method: HttpMethod, val mvcPatterns: Array<String>)
