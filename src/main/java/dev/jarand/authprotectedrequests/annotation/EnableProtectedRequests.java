package dev.jarand.authprotectedrequests.annotation;

import dev.jarand.authprotectedrequests.WebSecurityConfig;
import dev.jarand.authprotectedrequests.authapi.AuthApiClientConfig;
import dev.jarand.authprotectedrequests.authapi.AuthApiClientImpl;
import dev.jarand.authprotectedrequests.authapi.AuthApiClientMock;
import dev.jarand.authprotectedrequests.cookie.CookieServiceImpl;
import dev.jarand.authprotectedrequests.cookie.CookieServiceMock;
import dev.jarand.authprotectedrequests.jws.JwsServiceImpl;
import dev.jarand.authprotectedrequests.jws.JwsServiceMock;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(value = {
        WebSecurityConfig.class,
        JwsServiceImpl.class,
        JwsServiceMock.class,
        CookieServiceImpl.class,
        CookieServiceMock.class,
        AuthApiClientImpl.class,
        AuthApiClientMock.class,
        AuthApiClientConfig.class
})
public @interface EnableProtectedRequests {

    ProtectRequest[] protectedRequests();

    OpenRequest[] openRequests();
}
