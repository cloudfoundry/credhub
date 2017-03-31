package io.pivotal.security.service;

import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.BaseSecretSetRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
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

  public ResponseEntity performGenerate(
      AuditRecordBuilder auditRecordBuilder,
      BaseSecretGenerateRequest requestBody
  ) throws Exception {
    BaseSecretSetRequest setRequest = requestBody.generateSetRequest(generatorService);
    return setService.performSet(auditRecordBuilder, setRequest);
  }
}
