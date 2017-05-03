package io.pivotal.security.audit;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_DELETE;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.READ_ACL;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static io.pivotal.security.request.AccessControlOperation.WRITE_ACL;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.samePropertyValuesAs;

import io.pivotal.security.request.AccessControlEntry;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class EventAuditRecordParametersFactoryTest {

  @Test
  public void createPermissionsEventAuditParameters_returnsPermissionsEventsList() {
    String credentialName = "/test";
    List<AccessControlEntry> accessControlEntryList = asList(
        new AccessControlEntry("actor1", asList(READ, WRITE)),
        new AccessControlEntry("actor2", asList(READ_ACL, WRITE_ACL))
    );

    List<EventAuditRecordParameters> permissionsEventAuditParameters = EventAuditRecordParametersFactory
        .createPermissionsEventAuditParameters(
            ACL_UPDATE,
            credentialName,
            accessControlEntryList);

    assertThat(permissionsEventAuditParameters, containsInAnyOrder(
        samePropertyValuesAs(new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "actor1")),
        samePropertyValuesAs(new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE, "actor1")),
        samePropertyValuesAs(new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ_ACL, "actor2")),
        samePropertyValuesAs(new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE_ACL, "actor2"))
    ));
  }

  @Test
  public void createPermissionEventAuditRecordParameters_returnsPermissionsEventsList() {
    String credentialName = "/test";
    AccessControlEntry entry = new AccessControlEntry("actor1", asList(READ, WRITE));

    List<EventAuditRecordParameters> permissionsEventAuditParameters = EventAuditRecordParametersFactory
        .createPermissionEventAuditRecordParameters(
            ACL_DELETE,
            credentialName,
            entry);

    assertThat(permissionsEventAuditParameters, containsInAnyOrder(
        samePropertyValuesAs(new EventAuditRecordParameters(ACL_DELETE, credentialName, READ, "actor1")),
        samePropertyValuesAs(new EventAuditRecordParameters(ACL_DELETE, credentialName, WRITE, "actor1"))
    ));
  }
}
