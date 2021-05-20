package dev.jarand.authprotectedrequests.jws;

public interface JwsService {

    ParseClaimsResult parseClaims(String encodedJws);
}
