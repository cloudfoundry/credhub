package org.cloudfoundry.credhub.audit;

import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.samePropertyValuesAs;

@RunWith(JUnit4.class)
public class EventAuditRecordParametersFactoryTest {

  @Test
  public void createPermissionsEventAuditParameters_returnsPermissionsEventsList() {
    String credentialName = "/test";
    List<PermissionEntry> permissionEntryList = asList(
        new PermissionEntry("actor1", asList(PermissionOperation.READ, PermissionOperation.WRITE)),
        new PermissionEntry("actor2", asList(PermissionOperation.READ_ACL, PermissionOperation.WRITE_ACL))
    );

    List<EventAuditRecordParameters> permissionsEventAuditParameters = EventAuditRecordParametersFactory
        .createPermissionsEventAuditParameters(
            AuditingOperationCode.ACL_UPDATE,
            credentialName,
            permissionEntryList);

    assertThat(permissionsEventAuditParameters, containsInAnyOrder(
        samePropertyValuesAs(new EventAuditRecordParameters(AuditingOperationCode.ACL_UPDATE, credentialName, PermissionOperation.READ, "actor1")),
        samePropertyValuesAs(new EventAuditRecordParameters(AuditingOperationCode.ACL_UPDATE, credentialName, PermissionOperation.WRITE, "actor1")),
        samePropertyValuesAs(new EventAuditRecordParameters(AuditingOperationCode.ACL_UPDATE, credentialName, PermissionOperation.READ_ACL, "actor2")),
        samePropertyValuesAs(new EventAuditRecordParameters(AuditingOperationCode.ACL_UPDATE, credentialName, PermissionOperation.WRITE_ACL, "actor2"))
    ));
  }

  @Test
  public void createPermissionEventAuditRecordParameters_returnsPermissionsEventsList() {
    String credentialName = "/test";
    List<PermissionOperation> operations = newArrayList(PermissionOperation.READ, PermissionOperation.WRITE);

    List<EventAuditRecordParameters> permissionsEventAuditParameters = EventAuditRecordParametersFactory
        .createPermissionEventAuditRecordParameters(
            AuditingOperationCode.ACL_DELETE,
            credentialName,
            "actor1",
            operations
        );

    assertThat(permissionsEventAuditParameters, containsInAnyOrder(
        samePropertyValuesAs(new EventAuditRecordParameters(AuditingOperationCode.ACL_DELETE, credentialName, PermissionOperation.READ, "actor1")),
        samePropertyValuesAs(new EventAuditRecordParameters(AuditingOperationCode.ACL_DELETE, credentialName, PermissionOperation.WRITE, "actor1"))
    ));
  }
}
