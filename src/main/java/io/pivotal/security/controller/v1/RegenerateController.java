package io.pivotal.security.controller.v1;

import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.handler.RegenerateHandler;
import io.pivotal.security.request.BulkRegenerateRequest;
import io.pivotal.security.request.RegenerateRequest;
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
  private RegenerateHandler regenerateHandler;

  @Autowired
  public RegenerateController(
      RegenerateHandler regenerateHandler,
      EventAuditLogService eventAuditLogService
  ) {
    this.regenerateHandler = regenerateHandler;
    this.eventAuditLogService = eventAuditLogService;
  }

  @PostMapping(
      path = RegenerateController.API_V1_REGENERATE,
      produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView regenerate(
      UserContext userContext,
      RequestUuid requestUuid,
      @RequestBody @Validated RegenerateRequest requestBody
  ) throws IOException {
    return eventAuditLogService
        .auditEvents(requestUuid, userContext, (auditRecordParameters -> {
          return regenerateHandler
              .handleRegenerate(requestBody.getName(), userContext,
                  auditRecordParameters);
        }));
  }

  @PostMapping(
      path = RegenerateController.API_V1_BULK_REGENERATE,
      produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public BulkRegenerateResults bulkRegenerate(
      UserContext userContext,
      RequestUuid requestUuid,
      @RequestBody @Valid BulkRegenerateRequest requestBody
  ) throws IOException {
    return eventAuditLogService
        .auditEvents(requestUuid, userContext, (auditRecordParameters -> {
          return regenerateHandler
              .handleBulkRegenerate(requestBody.getSignedBy(), userContext,
                  auditRecordParameters);
        }));
  }
}
