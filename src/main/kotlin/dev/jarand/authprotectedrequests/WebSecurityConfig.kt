package dev.jarand.authprotectedrequests

import dev.jarand.authprotectedrequests.annotation.EnableProtectedRequests
import dev.jarand.authprotectedrequests.authapi.AuthApiClientImpl
import dev.jarand.authprotectedrequests.jws.JwsService
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider
import org.springframework.context.annotation.Configuration
import org.springframework.core.type.filter.AnnotationTypeFilter
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableWebSecurity
open class WebSecurityConfig(private val jwsServiceImpl: JwsService,
                             private val authApiClientImpl: AuthApiClientImpl) : WebSecurityConfigurerAdapter() {

    private val annotation: EnableProtectedRequests

    init {
        val provider = ClassPathScanningCandidateComponentProvider(false)
        provider.addIncludeFilter(AnnotationTypeFilter(EnableProtectedRequests::class.java))
        val beanDefinitions = provider.findCandidateComponents("*")
        if (beanDefinitions.size != 1) {
            throw IllegalStateException("Expected exactly one EnableProtectedRequests annotation, found ${beanDefinitions.size}")
        }
        annotation = Class.forName(beanDefinitions.toMutableList()[0].beanClassName).getAnnotation(EnableProtectedRequests::class.java)
    }

    override fun configure(http: HttpSecurity) {
        val interceptUrlRegistry = http.authorizeRequests()
        annotation.protectedRequests.forEach { interceptUrlRegistry.mvcMatchers(it.method, *it.mvcPatterns).hasRole(it.role) }

        http.authorizeRequests()
                .anyRequest().authenticated().and().httpBasic().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .csrf().disable()
                .addFilterBefore(BearerAuthenticationFilter(jwsServiceImpl, authApiClientImpl), UsernamePasswordAuthenticationFilter::class.java)

    }

    override fun configure(web: WebSecurity) {
        val ignoredConfigurer = web.ignoring()
        annotation.openRequests.forEach { ignoredConfigurer.mvcMatchers(it.method, *it.mvcPatterns) }
    }
}
