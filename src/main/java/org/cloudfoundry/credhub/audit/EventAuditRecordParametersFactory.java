package org.cloudfoundry.credhub.audit;

import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;

import java.util.List;
import java.util.stream.Collectors;

public class EventAuditRecordParametersFactory {
  public static List<EventAuditRecordParameters> createPermissionEventAuditRecordParameters(
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      String actor,
      List<PermissionOperation> operations
  ) {
    return operations.stream()
        .map(operation -> (
            new EventAuditRecordParameters(
                auditingOperationCode,
                credentialName,
                operation,
                actor
            )
        ))
        .collect(Collectors.toList());
  }

  public static List<EventAuditRecordParameters> createPermissionsEventAuditParameters(
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      List<PermissionEntry> accessControlEntries
  ) {
    return accessControlEntries.stream()
        .map(entry -> {
          String actor = entry.getActor();
          return entry.getAllowedOperations().stream()
              .map(operation -> (
                new EventAuditRecordParameters(
                    auditingOperationCode,
                    credentialName,
                    operation,
                    actor
                )
              ))
              .collect(Collectors.toList());
        })
        .flatMap(List::stream)
        .collect(Collectors.toList());
  }
}
