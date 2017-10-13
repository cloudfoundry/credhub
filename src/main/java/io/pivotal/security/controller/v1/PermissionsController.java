package io.pivotal.security.controller.v1;

import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.EventAuditRecordParameters;
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

  @Autowired
  public PermissionsController(
      PermissionsHandler permissionsHandler,
      EventAuditLogService eventAuditLogService) {
    this.permissionsHandler = permissionsHandler;
    this.eventAuditLogService = eventAuditLogService;
  }

  @GetMapping
  @ResponseStatus(HttpStatus.OK)
  public PermissionsView getAccessControlList(@RequestParam("credential_name") String credentialName) throws Exception {
    return eventAuditLogService
        .auditEvents(auditRecordParameters -> {
          return permissionsHandler
              .getPermissions(credentialName, auditRecordParameters);
        });
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  public void setAccessControlEntries(@Validated @RequestBody PermissionsRequest accessEntriesRequest) {
    eventAuditLogService.auditEvents(auditRecordParameters -> {
      permissionsHandler.setPermissions(accessEntriesRequest, auditRecordParameters);
      return null;
    });
  }

  @DeleteMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteAccessControlEntry(
      @RequestParam("credential_name") String credentialName,
      @RequestParam("actor") String actor
  ) {
    eventAuditLogService.auditEvents(
        (List<EventAuditRecordParameters> auditRecordParameters) -> {
          permissionsHandler.deletePermissionEntry(credentialName, actor, auditRecordParameters);
          return true;
        });
  }
}
