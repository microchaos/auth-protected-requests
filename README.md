# auth-protected-requests
Library for protecting applications and authorize users authenticated with JarandDev Authentication

### How to

1. Add dependency
```xml
<dependency>
    <groupId>dev.jarand</groupId>
    <artifactId>auth-protected-requests</artifactId>
    <version>Check version on Maven Central or GitHub Releases</version>
</dependency>
```
Maven Central: [Link](https://search.maven.org/artifact/dev.jarand/auth-protected-requests)
GitHub Releases: [Link](https://github.com/JarandDev/auth-protected-requests/releases)

2. Configure URLs to the authentication api:
```
authentication.api.base-url=http://foo.bar/api
authentication.api.endpoint.public-key=http://foo.bar/api/key/public
authentication.api.endpoint.refresh-token=http://foo.bar/api/refresh-token
```
The key needs to be exposed in a JSON object like the following:
```json
{
  "key": "Base 64 encoded public key"
}
```
3. Configure the access token cookie
```
authentication.cookie.name=access_token
authentication.cookie.httpOnly=true
authentication.cookie.secure=true
authentication.cookie.domain=foo.bar
authentication.cookie.path=/
authentication.cookie.maxAge=600
```
4. Add annotation with endpoints that should be protected and open:
```kotlin
@Configuration
@EnableProtectedRequests(
        protectedRequests = [
            ProtectRequest(
                    method = HttpMethod.GET,
                    mvcPatterns = ["/secured/**"],
                    role = "test-api.read"
            ),
            ProtectRequest(
                    method = HttpMethod.POST,
                    mvcPatterns = ["/data"],
                    role = "test-api.write"
            )
        ],
        openRequests = [
            OpenRequest(
                    method = HttpMethod.GET,
                    mvcPatterns = [
                        "/api-docs"
                    ])
        ]
)
class SecurityConfig
```

### Test
You can use the following properties if you want to test the functionality in an environment without an authentication service:
```
authentication.mock.enabled=true
authentication.mock.scope=test-api.read test-api.write
```
