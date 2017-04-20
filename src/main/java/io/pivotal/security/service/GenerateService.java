package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.view.CredentialView;
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

  public CredentialView performGenerate(EventAuditRecordParameters eventAuditRecordParameters, BaseCredentialGenerateRequest requestBody, AccessControlEntry currentUserAccessControlEntry) {
    BaseCredentialSetRequest setRequest = requestBody.generateSetRequest(generatorService);
    return setService.performSet(eventAuditRecordParameters, setRequest, currentUserAccessControlEntry);
  }
}
