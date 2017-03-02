package io.pivotal.security.request;

import org.codehaus.jackson.annotate.JsonAutoDetect;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.List;

@JsonAutoDetect
public class AccessEntryRequest {

    @NotNull
    private String credentialName;

    @SuppressWarnings("unused")
    public AccessEntryRequest() {
        /* this needs to be there for jackson to be happy */
    }

    public AccessEntryRequest(String credentialName, List<AccessControlEntry> accessControlEntries) {
        this.credentialName = credentialName;
        this.accessControlEntries = accessControlEntries;
    }

    @NotNull
    private List<AccessControlEntry> accessControlEntries;

    public String getCredentialName() {
        return credentialName;
    }

    public void setCredentialName(String credentialName) {
        this.credentialName = credentialName;
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
