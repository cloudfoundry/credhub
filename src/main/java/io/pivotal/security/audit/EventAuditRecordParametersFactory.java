package io.pivotal.security.audit;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Collections.singletonList;

import io.pivotal.security.request.AccessControlEntry;
import java.util.List;

public class EventAuditRecordParametersFactory {
  public static List<EventAuditRecordParameters> createPermissionEventAuditRecordParameters(
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      AccessControlEntry accessControlEntry
  ) {
    return createPermissionsEventAuditParameters(
        auditingOperationCode,
        credentialName,
        singletonList(accessControlEntry)
    );
  }

  public static List<EventAuditRecordParameters> createPermissionsEventAuditParameters(
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      List<AccessControlEntry> accessControlEntries
  ) {
    List<EventAuditRecordParameters> eventAuditRecordParameters = newArrayList();
    accessControlEntries.stream()
        .forEach(entry -> {
          String actor = entry.getActor();
          entry.getAllowedOperations().stream()
              .forEach(operation -> {
                eventAuditRecordParameters.add(new EventAuditRecordParameters(
                    auditingOperationCode,
                    credentialName,
                    operation,
                    actor));
              });
        });
    return eventAuditRecordParameters;
  }
}
