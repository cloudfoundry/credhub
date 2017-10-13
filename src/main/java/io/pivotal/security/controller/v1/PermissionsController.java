package io.pivotal.security.controller.v1;

import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.auth.UserContextHolder;
import io.pivotal.security.handler.PermissionsHandler;
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

@RestController
@RequestMapping(path = "/api/v1/permissions", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class PermissionsController {

  private final PermissionsHandler permissionsHandler;
  private final EventAuditLogService eventAuditLogService;
  private final UserContextHolder userContextHolder;

  @Autowired
  public PermissionsController(
      PermissionsHandler permissionsHandler,
      EventAuditLogService eventAuditLogService,
      UserContextHolder userContextHolder) {
    this.permissionsHandler = permissionsHandler;
    this.eventAuditLogService = eventAuditLogService;
    this.userContextHolder = userContextHolder;
  }

  @GetMapping
  @ResponseStatus(HttpStatus.OK)
  public PermissionsView getAccessControlList(
      @RequestParam("credential_name") String credentialName,
      RequestUuid requestUuid,
      UserContext userContext
  ) throws Exception {
    userContextHolder.setUserContext(userContext);
    return eventAuditLogService
        .auditEvents(requestUuid, auditRecordParameters -> {
          return permissionsHandler
              .getPermissions(credentialName, auditRecordParameters);
        });
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  public void setAccessControlEntries(
      RequestUuid requestUuid,
      UserContext userContext,
      @Validated @RequestBody PermissionsRequest accessEntriesRequest
  ) {
    userContextHolder.setUserContext(userContext);
    eventAuditLogService.auditEvents(requestUuid, auditRecordParameters -> {
      permissionsHandler.setPermissions(accessEntriesRequest, auditRecordParameters);
      return null;
    });
  }

  @DeleteMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteAccessControlEntry(
      RequestUuid requestUuid, UserContext userContext,
      @RequestParam("credential_name") String credentialName,
      @RequestParam("actor") String actor
  ) {
    userContextHolder.setUserContext(userContext);
    eventAuditLogService.auditEvents(requestUuid,
        (List<EventAuditRecordParameters> auditRecordParameters) -> {
          permissionsHandler.deletePermissionEntry(credentialName, actor, auditRecordParameters);
          return true;
        });
  }
}
