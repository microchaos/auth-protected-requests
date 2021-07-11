package dev.jarand.authprotectedrequests.annotation;

import dev.jarand.authprotectedrequests.AuthApiClient;
import dev.jarand.authprotectedrequests.AuthApiClientConfig;
import dev.jarand.authprotectedrequests.TokenService;
import dev.jarand.authprotectedrequests.WebSecurityConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import({
        WebSecurityConfig.class,
        TokenService.class,
        AuthApiClient.class,
        AuthApiClientConfig.class})
public @interface EnableProtectedRequests {

    ProtectRequest[] protectedRequests();

    OpenRequest[] openRequests();
}
