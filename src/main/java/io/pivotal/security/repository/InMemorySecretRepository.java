package io.pivotal.security.repository;

import io.pivotal.security.entity.Secret;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class InMemorySecretRepository implements SecretRepository {

    private Map<String, Secret> secrets;

    public InMemorySecretRepository() {
        this.secrets = new HashMap<>();
    }

    @Override
    public void set(String key, Secret secret) {
        secrets.put(key, secret);
    }

    @Override
    public Secret get(String key) {
        return secrets.get(key);
    }
}
