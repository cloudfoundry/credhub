package io.pivotal.security.entity;

import java.util.Map;

public class Secret {
    private Map<String, String> values;

    public Secret() {
    }

    public Secret(Map<String, String> values) {
        this.values = values;
    }

    public Map<String, String> getValues() {
        return values;
    }

    public void setValues(Map<String, String> values) {
        this.values = values;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        Secret secret = (Secret) obj;

        return values != null ? values.equals(secret.values) : secret.values == null;
    }

    @Override
    public int hashCode() {
        return values != null ? values.hashCode() : 0;
    }
}
