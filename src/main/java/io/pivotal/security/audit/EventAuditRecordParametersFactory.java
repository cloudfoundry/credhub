package io.pivotal.security.audit;

import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;

import java.util.List;
import java.util.stream.Collectors;

public class EventAuditRecordParametersFactory {
  public static List<EventAuditRecordParameters> createPermissionEventAuditRecordParameters(
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      String actor,
      List<AccessControlOperation> operations
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
      List<AccessControlEntry> accessControlEntries
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
