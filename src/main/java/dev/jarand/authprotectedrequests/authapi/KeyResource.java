package dev.jarand.authprotectedrequests.authapi;

public class KeyResource {

    private final String key;

    public KeyResource(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }
}
