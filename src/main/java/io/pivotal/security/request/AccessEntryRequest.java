package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.codehaus.jackson.annotate.JsonAutoDetect;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.List;

@JsonAutoDetect
public class AccessEntryRequest {

    @NotNull
    private String resource;

    @SuppressWarnings("unused")
    public AccessEntryRequest() {
        /* this needs to be there for jackson to be happy */
    }

    public AccessEntryRequest(String resource, List<AccessControlEntry> accessControlEntries) {
        this.resource = resource;
        this.accessControlEntries = accessControlEntries;
    }

    @NotNull
    @JsonProperty("access_control_entries")
    private List<AccessControlEntry> accessControlEntries;

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    @Valid
    public List<AccessControlEntry> getAccessControlEntries() {
        return accessControlEntries;
    }

    @SuppressWarnings("unused")
    public void setAccessControlEntries(List<AccessControlEntry> accessControlEntries) {
        this.accessControlEntries = accessControlEntries;
    }
}
