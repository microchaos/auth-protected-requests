package dev.jarand.authprotectedrequests;

import dev.jarand.authprotectedrequests.annotation.EnableProtectedRequests;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;

import java.util.Arrays;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final TokenService tokenService;
    private final EnableProtectedRequests annotation;

    public WebSecurityConfig(TokenService tokenService) throws ClassNotFoundException {
        this.tokenService = tokenService;

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
                        .access(protectedRequest.access()));

        http.authorizeRequests()
                .anyRequest().authenticated().and()
                .sessionManagement().sessionCreationPolicy(STATELESS).and()
                .csrf().disable()
                .addFilterBefore(new BearerAuthenticationFilter(tokenService), RequestCacheAwareFilter.class);

    }

    @Override
    public void configure(WebSecurity web) {
        final var ignoredConfigurer = web.ignoring();
        Arrays.asList(annotation.openRequests()).forEach(openRequest -> ignoredConfigurer.mvcMatchers(openRequest.method(), openRequest.mvcPatterns()));
    }
}
