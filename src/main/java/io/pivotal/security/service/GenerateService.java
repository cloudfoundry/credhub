package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordBuilder;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.view.SecretView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class GenerateService {

  private final GeneratorService generatorService;
  private final SetService setService;

  @Autowired
  public GenerateService(GeneratorService generatorService, SetService setService) {
    this.generatorService = generatorService;
    this.setService = setService;
  }

  public SecretView performGenerate(EventAuditRecordBuilder auditRecordBuilder, BaseSecretGenerateRequest requestBody, AccessControlEntry currentUserAccessControlEntry) {
    BaseSecretSetRequest setRequest = requestBody.generateSetRequest(generatorService);
    return setService.performSet(auditRecordBuilder, setRequest, currentUserAccessControlEntry);
  }
}
