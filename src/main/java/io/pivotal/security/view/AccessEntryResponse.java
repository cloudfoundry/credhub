package io.pivotal.security.view;

import io.pivotal.security.request.AccessControlEntry;
import org.codehaus.jackson.annotate.JsonAutoDetect;

import java.util.List;

@JsonAutoDetect
public class AccessEntryResponse {

    private String credentialName;
    private List<AccessControlEntry> acls;

    public AccessEntryResponse() {
    }

    public AccessEntryResponse(String credentialName, List<AccessControlEntry> acls) {
        this.credentialName = credentialName;
        this.acls = acls;
    }

    public String getCredentialName() {
        return credentialName;
    }

    public void setCredentialName(String credentialName) {
        this.credentialName = credentialName;
    }

    public List<AccessControlEntry> getAcls() {
        return acls;
    }

    public void setAcls(List<AccessControlEntry> acls) {
        this.acls = acls;
    }
}
