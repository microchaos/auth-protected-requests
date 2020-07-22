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
GitHub Releases: [Link](https://github.com/microchaos/auth-protected-requests/releases)

2. Configure URL of the exposed public key:
```
auth-api.base-url=http://foo.bar/key/public
```
The key needs to be exposed in a JSON object like the following:
```json
{
  "key": "Base 64 encoded public key"
}
```

3. Add annotation with endpoints that should be protected and open:
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
