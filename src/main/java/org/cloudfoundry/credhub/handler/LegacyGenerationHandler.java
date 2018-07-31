package org.cloudfoundry.credhub.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entity.GenerateCredential;
import org.cloudfoundry.credhub.audit.entity.RegenerateCredential;
import org.cloudfoundry.credhub.exceptions.InvalidAdditionalPermissionsException;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.CredentialRegenerateRequest;
import org.cloudfoundry.credhub.request.PermissionEntry;
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
  private CEFAuditRecord auditRecord;

  @Autowired
  public LegacyGenerationHandler(ObjectMapper objectMapper,
      GenerateHandler generateHandler,
      RegenerateHandler regenerateHandler,
      CEFAuditRecord auditRecord) {
    this.objectMapper = objectMapper;
    this.generateHandler = generateHandler;
    this.regenerateHandler = regenerateHandler;
    this.auditRecord = auditRecord;
  }

  public CredentialView auditedHandlePostRequest(InputStream inputStream) {
    return deserializeAndHandlePostRequest(inputStream);
  }

  //when versions prior to 1.6 are no longer LTS, this branching logic to support generate and regenerate on the same endpoint will be removed
  private CredentialView deserializeAndHandlePostRequest(InputStream inputStream) {
    try {
      String requestString = StringUtil.fromInputStream(inputStream);

      if (readRegenerateFlagFrom(requestString)) {
        return handleRegenerateRequest(requestString);
      } else {
        return handleGenerateRequest(requestString);
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private CredentialView handleGenerateRequest(String requestString) throws IOException {
    BaseCredentialGenerateRequest requestBody = objectMapper
        .readValue(requestString, BaseCredentialGenerateRequest.class);
    requestBody.validate();

    String credentialName = requestBody.getName();

    GenerateCredential generateCredential = new GenerateCredential();
    generateCredential.setName(credentialName);
    generateCredential.setType(requestBody.getType());

    List<PermissionEntry> permissionEntries = requestBody.getAdditionalPermissions();
    permissionEntries.forEach(i -> validatePermissionAndPath(i, credentialName));

    generateCredential.setAdditionalPermissions(permissionEntries);
    auditRecord.setRequestDetails(generateCredential);

    return generateHandler.handle(requestBody);
  }

  private void validatePermissionAndPath(PermissionEntry entry, String credentialName) {
    if(entry.getPath() != null){
      throw new InvalidAdditionalPermissionsException("path");
    }
    entry.setPath(credentialName);
  }

  private CredentialView handleRegenerateRequest(String requestString) throws IOException {
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
