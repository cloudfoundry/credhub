package io.pivotal.security.controller.v1;

import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.handler.PermissionsHandler;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.request.PermissionsRequest;
import io.pivotal.security.view.PermissionsView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_DELETE;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionEventAuditRecordParameters;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionsEventAuditParameters;

@RestController
@RequestMapping(path = "/api/v1/permissions", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class PermissionsController {
  private final PermissionsHandler permissionsHandler;
  private final EventAuditLogService eventAuditLogService;
  private PermissionsDataService permissionsDataService;

  @Autowired
  public PermissionsController(
      PermissionsHandler permissionsHandler,
      EventAuditLogService eventAuditLogService,
      PermissionsDataService permissionsDataService
  ) {
    this.permissionsHandler = permissionsHandler;
    this.eventAuditLogService = eventAuditLogService;
    this.permissionsDataService = permissionsDataService;
  }

  @GetMapping
  @ResponseStatus(HttpStatus.OK)
  public PermissionsView getAccessControlList(
    @RequestParam("credential_name") String credentialName,
    RequestUuid requestUuid,
    UserContext userContext
  ) throws Exception {
    return eventAuditLogService.auditEvents(requestUuid, userContext, eventAuditRecordParametersList -> {
      EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(
          ACL_ACCESS, credentialName
      );
      eventAuditRecordParametersList.add(eventAuditRecordParameters);

      final PermissionsView response = permissionsHandler.getPermissions(userContext, credentialName);

      eventAuditRecordParameters.setCredentialName(response.getCredentialName());

      return response;
    });
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public PermissionsView setAccessControlEntries(
      RequestUuid requestUuid,
      UserContext userContext,
      @Validated @RequestBody PermissionsRequest accessEntriesRequest
  ) {
    return eventAuditLogService.auditEvents(requestUuid, userContext, auditRecordParameters -> {
      auditRecordParameters.addAll(createPermissionsEventAuditParameters(
          ACL_UPDATE,
          accessEntriesRequest.getCredentialName(),
          accessEntriesRequest.getPermissions())
      );
      return permissionsHandler.setPermissions(
          userContext,
          accessEntriesRequest.getCredentialName(),
          accessEntriesRequest.getPermissions()
      );
    });
  }

  @DeleteMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteAccessControlEntry(
      @RequestParam("credential_name") String credentialName,
      @RequestParam("actor") String actor,
      RequestUuid requestUuid,
      UserContext userContext

  ) {
    eventAuditLogService.auditEvents(requestUuid, userContext, auditRecordParameters -> {
      List<PermissionOperation> operationList = permissionsDataService
          .getAllowedOperations(credentialName, actor);

      auditRecordParameters.addAll(createPermissionEventAuditRecordParameters(
          ACL_DELETE,
          credentialName,
          actor,
          operationList
      ));

      permissionsHandler.deletePermissionEntry(userContext, credentialName, actor);

      return true;
    });
  }
}
