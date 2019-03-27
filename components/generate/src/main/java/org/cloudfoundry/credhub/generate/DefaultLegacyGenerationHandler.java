package org.cloudfoundry.credhub.generate;

import java.io.IOException;
import java.io.InputStream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entities.GenerateCredential;
import org.cloudfoundry.credhub.audit.entities.RegenerateCredential;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.CredentialRegenerateRequest;
import org.cloudfoundry.credhub.utils.StringUtil;
import org.cloudfoundry.credhub.views.CredentialView;

@Component
public class DefaultLegacyGenerationHandler implements LegacyGenerationHandler {

  private final ObjectMapper objectMapper;
  private final GenerateHandler generateHandler;
  private final RegenerateHandler regenerateHandler;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public DefaultLegacyGenerationHandler(
    final ObjectMapper objectMapper,
    final GenerateHandler generateHandler,
    final RegenerateHandler regenerateHandler,
    final CEFAuditRecord auditRecord
  ) {
    super();
    this.objectMapper = objectMapper;
    this.generateHandler = generateHandler;
    this.regenerateHandler = regenerateHandler;
    this.auditRecord = auditRecord;
  }

  @Override
  public CredentialView auditedHandlePostRequest(final InputStream inputStream) {
    return deserializeAndHandlePostRequest(inputStream);
  }

  //when versions prior to 1.6 are no longer LTS, this branching logic to support generate and regenerate on the same endpoint will be removed
  private CredentialView deserializeAndHandlePostRequest(final InputStream inputStream) {
    try {
      final String requestString = StringUtil.fromInputStream(inputStream);

      if (readRegenerateFlagFrom(requestString)) {
        return handleRegenerateRequest(requestString);
      } else {
        return handleGenerateRequest(requestString);
      }
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
  }

  private CredentialView handleGenerateRequest(final String requestString) throws IOException {
    final BaseCredentialGenerateRequest requestBody = objectMapper
      .readValue(requestString, BaseCredentialGenerateRequest.class);

    final String credentialName = requestBody.getName();

    final GenerateCredential generateCredential = new GenerateCredential();
    generateCredential.setName(credentialName);
    generateCredential.setType(requestBody.getType());
    auditRecord.setRequestDetails(generateCredential);
    requestBody.validate();

    return generateHandler.handle(requestBody);
  }

  private CredentialView handleRegenerateRequest(final String requestString) throws IOException {
    final CredentialRegenerateRequest requestBody = objectMapper.readValue(requestString, CredentialRegenerateRequest.class);
    requestBody.validate();

    final RegenerateCredential regenerateCredential = new RegenerateCredential();
    regenerateCredential.setName(requestBody.getName());
    auditRecord.setRequestDetails(regenerateCredential);

    return regenerateHandler.handleRegenerate(requestBody.getName());
  }


  private boolean readRegenerateFlagFrom(final String requestString) {
    boolean isRegenerateRequest;
    try {
      isRegenerateRequest = JsonPath.read(requestString, "$.regenerate");
    } catch (final PathNotFoundException e) {
      // could have just returned null, that would have been pretty useful
      isRegenerateRequest = false;
    } catch (final IllegalArgumentException e) {
      return false;
    }
    return isRegenerateRequest;
  }
}
