package org.cloudfoundry.credhub.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.EventAuditLogService;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.audit.entity.GenerateCredential;
import org.cloudfoundry.credhub.audit.entity.RegenerateCredential;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.CredentialRegenerateRequest;
import org.cloudfoundry.credhub.util.StringUtil;
import org.cloudfoundry.credhub.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

@Component
public class LegacyGenerationHandler {


  private final ObjectMapper objectMapper;
  private final GenerateHandler generateHandler;
  private final RegenerateHandler regenerateHandler;
  private final EventAuditLogService eventAuditLogService;
  private CEFAuditRecord auditRecord;

  @Autowired
  public LegacyGenerationHandler(ObjectMapper objectMapper,
                                 GenerateHandler generateHandler,
                                 RegenerateHandler regenerateHandler,
                                 EventAuditLogService eventAuditLogService,
                                 CEFAuditRecord auditRecord) {
    this.objectMapper = objectMapper;
    this.generateHandler = generateHandler;
    this.regenerateHandler = regenerateHandler;
    this.eventAuditLogService = eventAuditLogService;
    this.auditRecord = auditRecord;
  }

  public CredentialView auditedHandlePostRequest(InputStream inputStream) {
    return eventAuditLogService
        .auditEvents((auditRecordParameters -> deserializeAndHandlePostRequest(inputStream, auditRecordParameters)));
  }

  //when versions prior to 1.6 are no longer LTS, this branching logic to support generate and regenerate on the same endpoint will be removed
  private CredentialView deserializeAndHandlePostRequest(
      InputStream inputStream,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    try {
      String requestString = StringUtil.fromInputStream(inputStream);

      if (readRegenerateFlagFrom(requestString)) {
        return handleRegenerateRequest(requestString, auditRecordParameters);
      } else {
        return handleGenerateRequest(auditRecordParameters, requestString
        );
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private CredentialView handleGenerateRequest(
      List<EventAuditRecordParameters> auditRecordParameters,
      String requestString
  ) throws IOException {
    BaseCredentialGenerateRequest requestBody = objectMapper.readValue(requestString, BaseCredentialGenerateRequest.class);
    requestBody.validate();

    GenerateCredential generateCredential = new GenerateCredential();
    generateCredential.setName(requestBody.getName());
    generateCredential.setMode(requestBody.getMode());
    generateCredential.setType(requestBody.getType());
    generateCredential.setAdditionalPermissions(requestBody.getAdditionalPermissions());
    auditRecord.setRequestDetails(generateCredential);

    return generateHandler.handle(requestBody, auditRecordParameters);
  }

  private CredentialView handleRegenerateRequest(
      String requestString, List<EventAuditRecordParameters> auditRecordParameters
  ) throws IOException {
    CredentialRegenerateRequest requestBody = objectMapper.readValue(requestString, CredentialRegenerateRequest.class);
    requestBody.validate();

    RegenerateCredential regenerateCredential = new RegenerateCredential();
    regenerateCredential.setName(requestBody.getName());
    auditRecord.setRequestDetails(regenerateCredential);

    return regenerateHandler.handleRegenerate(requestBody.getName());
  }


  private boolean readRegenerateFlagFrom(String requestString) {
    boolean isRegenerateRequest;
    try {
      isRegenerateRequest = JsonPath.read(requestString, "$.regenerate");
    } catch (PathNotFoundException e) {
      // could have just returned null, that would have been pretty useful
      isRegenerateRequest = false;
    } catch (IllegalArgumentException e) {
      return false;
    }
    return isRegenerateRequest;
  }
}
