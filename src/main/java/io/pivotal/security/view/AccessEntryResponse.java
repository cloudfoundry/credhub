package io.pivotal.security.view;

import io.pivotal.security.request.AccessControlEntry;
import org.codehaus.jackson.annotate.JsonAutoDetect;

import java.util.List;

@JsonAutoDetect
public class AccessEntryResponse {

    private String resource;
    private List<AccessControlEntry> acls;

    public AccessEntryResponse() {
    }

    public AccessEntryResponse(String resource, List<AccessControlEntry> acls) {
        this.resource = resource;
        this.acls = acls;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public List<AccessControlEntry> getAcls() {
        return acls;
    }

    public void setAcls(List<AccessControlEntry> acls) {
        this.acls = acls;
    }
}
