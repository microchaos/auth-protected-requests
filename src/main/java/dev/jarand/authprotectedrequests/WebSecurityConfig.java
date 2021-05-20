package dev.jarand.authprotectedrequests;

import dev.jarand.authprotectedrequests.annotation.EnableProtectedRequests;
import dev.jarand.authprotectedrequests.authapi.AuthApiClient;
import dev.jarand.authprotectedrequests.cookie.CookieService;
import dev.jarand.authprotectedrequests.jws.JwsService;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwsService jwsServiceImpl;
    private final CookieService cookieServiceImpl;
    private final AuthApiClient authApiClientImpl;
    private final EnableProtectedRequests annotation;

    public WebSecurityConfig(JwsService jwsServiceImpl, CookieService cookieServiceImpl, AuthApiClient authApiClientImpl) throws ClassNotFoundException {
        this.jwsServiceImpl = jwsServiceImpl;
        this.cookieServiceImpl = cookieServiceImpl;
        this.authApiClientImpl = authApiClientImpl;

        final var provider = new ClassPathScanningCandidateComponentProvider(false);
        provider.addIncludeFilter(new AnnotationTypeFilter(EnableProtectedRequests.class));
        final var beanDefinitions = provider.findCandidateComponents("*");
        if (beanDefinitions.size() != 1) {
            throw new IllegalStateException("Expected exactly one EnableProtectedRequests annotation, found " + beanDefinitions.size());
        }
        annotation = Class.forName(beanDefinitions.toArray(new BeanDefinition[1])[0].getBeanClassName()).getAnnotation(EnableProtectedRequests.class);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        final var interceptUrlRegistry = http.authorizeRequests();
        Arrays.asList(annotation.protectedRequests())
                .forEach(protectedRequest -> interceptUrlRegistry
                        .mvcMatchers(protectedRequest.method(), protectedRequest.mvcPatterns())
                        .hasRole(protectedRequest.role()));

        http.authorizeRequests()
                .anyRequest().authenticated().and().httpBasic().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .csrf().disable()
                .addFilterBefore(new BearerAuthenticationFilter(jwsServiceImpl, cookieServiceImpl, authApiClientImpl), UsernamePasswordAuthenticationFilter.class);

    }

    @Override
    public void configure(WebSecurity web) {
        final var ignoredConfigurer = web.ignoring();
        Arrays.asList(annotation.openRequests()).forEach(openRequest -> ignoredConfigurer.mvcMatchers(openRequest.method(), openRequest.mvcPatterns()));
    }
}
