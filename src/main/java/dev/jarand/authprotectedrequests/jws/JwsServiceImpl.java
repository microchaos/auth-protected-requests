package dev.jarand.authprotectedrequests.jws;

import dev.jarand.authprotectedrequests.authapi.AuthApiClientImpl;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.security.PublicKey;

@Service
@ConditionalOnProperty(name = "authentication.mock.enabled", havingValue = "false", matchIfMissing = true)
public class JwsServiceImpl implements JwsService {

    private static final Logger logger = LoggerFactory.getLogger(JwsServiceImpl.class);

    private final AuthApiClientImpl authApiClientImpl;
    private PublicKey publicKey;

    public JwsServiceImpl(AuthApiClientImpl authApiClientImpl) {
        this.authApiClientImpl = authApiClientImpl;
    }

    @Override
    public ParseClaimsResult parseClaims(String encodedJws) {
        if (publicKey == null) {
            logger.debug("No public key. Fetching public key.");
            publicKey = authApiClientImpl.fetchPublicKey();
        }
        final var result = attemptParsing(encodedJws);
        if (result.getState() == ParseClaimsResultState.INVALID_SIGNATURE) {
            logger.debug("Invalid signature. Fetching public key again.");
            publicKey = authApiClientImpl.fetchPublicKey();
        }
        return attemptParsing(encodedJws);
    }

    private ParseClaimsResult attemptParsing(String encodedJws) {
        try {
            final var jws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(encodedJws);
            return new ParseClaimsResult(ParseClaimsResultState.SUCCESS, jws.getBody());
        } catch (ExpiredJwtException ex) {
            return new ParseClaimsResult(ParseClaimsResultState.EXPIRED, null);
        } catch (SignatureException ex) {
            return new ParseClaimsResult(ParseClaimsResultState.INVALID_SIGNATURE, null);
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException ex) {
            return new ParseClaimsResult(ParseClaimsResultState.INVALID_FORMAT, null);
        } catch (Throwable throwable) {
            throw new IllegalStateException("Unhandled throwable", throwable);
        }
    }
}
