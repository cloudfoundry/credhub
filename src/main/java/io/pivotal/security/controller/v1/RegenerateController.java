package io.pivotal.security.controller.v1;

import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.request.BulkRegenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.RegenerateRequest;
import io.pivotal.security.service.RegenerateService;
import io.pivotal.security.view.BulkRegenerateResults;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import javax.validation.Valid;

@RestController
public class RegenerateController {
  static final String API_V1_REGENERATE = "api/v1/regenerate";
  static final String API_V1_BULK_REGENERATE = "api/v1/bulk-regenerate";

  private final EventAuditLogService eventAuditLogService;
  private RegenerateService regenerateService;

  @Autowired
  public RegenerateController(
      RegenerateService regenerateService,
      EventAuditLogService eventAuditLogService
  ) {
    this.regenerateService = regenerateService;
    this.eventAuditLogService = eventAuditLogService;
  }

  @PostMapping(
      path = RegenerateController.API_V1_REGENERATE,
      produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView regenerate(
      UserContext userContext,
      RequestUuid requestUuid,
      PermissionEntry currentUserPermissionEntry,
      @RequestBody @Validated RegenerateRequest requestBody
  ) throws IOException {
    return eventAuditLogService
        .auditEvents(requestUuid, userContext, (auditRecordParameters -> {
          return regenerateService
              .performRegenerate(requestBody.getName(), userContext,
                  currentUserPermissionEntry, auditRecordParameters);
        }));
  }

  @PostMapping(
      path = RegenerateController.API_V1_BULK_REGENERATE,
      produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public BulkRegenerateResults bulkRegenerate(
      UserContext userContext,
      RequestUuid requestUuid,
      PermissionEntry currentUserPermissionEntry,
      @RequestBody @Valid BulkRegenerateRequest requestBody
  ) throws IOException {
    return eventAuditLogService
        .auditEvents(requestUuid, userContext, (auditRecordParameters -> {
          return regenerateService
              .performBulkRegenerate(requestBody.getSignedBy(), userContext,
                  currentUserPermissionEntry, auditRecordParameters);
        }));
  }
}
