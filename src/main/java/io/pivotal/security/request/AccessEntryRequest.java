package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.codehaus.jackson.annotate.JsonAutoDetect;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.List;

@JsonAutoDetect
public class AccessEntryRequest {

    @NotNull
    @JsonProperty("credential_name")
    private String credentialName;

    @SuppressWarnings("unused")
    public AccessEntryRequest() {
        /* this needs to be there for jackson to be happy */
    }

    public AccessEntryRequest(String credentialName, List<AccessControlEntry> accessControlList) {
        this.credentialName = credentialName;
        this.accessControlList = accessControlList;
    }

    @NotNull
    @JsonProperty("access_control_list")
    private List<AccessControlEntry> accessControlList;

    public String getCredentialName() {
        return credentialName;
    }

    public void setCredentialName(String credentialName) {
        this.credentialName = credentialName;
    }

    @Valid
    public List<AccessControlEntry> getAccessControlList() {
        return accessControlList;
    }

    @SuppressWarnings("unused")
    public void setAccessControlList(List<AccessControlEntry> accessControlList) {
        this.accessControlList = accessControlList;
    }
}
