package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;

@Service
public class JsonInterpolationService {
  private CredentialDataService credentialDataService;

  @Autowired
  public JsonInterpolationService(CredentialDataService credentialDataService) {
    this.credentialDataService = credentialDataService;
  }

  public Map<String, Object> interpolateCredHubReferences(Map<String, Object> servicesMap,
      List<EventAuditRecordParameters> eventAuditRecordParameters) {

    for (Object serviceProperties : servicesMap.values()) {
      if (serviceProperties == null || !(serviceProperties instanceof ArrayList)) {
        continue;
      }
      for (Object properties : (ArrayList) serviceProperties) {
        if (!(properties instanceof Map)) {
          continue;
        }
        Map<String, Object> propertiesMap = (Map) properties;
        Object credentials = propertiesMap.get("credentials");
        if (credentials == null || !(credentials instanceof Map)) {
          continue;
        }
        // Allow either snake_case or kebab-case
        Object credhubRef = ((Map) credentials).get("credhub_ref");
        if (credhubRef == null) {
          credhubRef = ((Map) credentials).get("credhub-ref");
        }

        if (credhubRef == null || !(credhubRef instanceof String)) {
          continue;
        }
        String credentialName = getCredentialNameFromRef((String) credhubRef);

        Credential credential = credentialDataService.findMostRecent(credentialName);
        if (credential == null) {
          eventAuditRecordParameters
              .add(new EventAuditRecordParameters(CREDENTIAL_ACCESS, credentialName));

          throw new ParameterizedValidationException("error.interpolation.invalid_access");
        }

        eventAuditRecordParameters
            .add(new EventAuditRecordParameters(CREDENTIAL_ACCESS, credential.getName()));

        if (credential instanceof JsonCredential) {
          propertiesMap.put("credentials", ((JsonCredential) credential).getValue());
        } else {
          throw new ParameterizedValidationException("error.interpolation.invalid_type",
              credentialName);
        }
      }
    }
    return servicesMap;
  }

  private String getCredentialNameFromRef(String credhubRef) {
    return credhubRef.replaceFirst("^\\(\\(", "").replaceFirst("\\)\\)$", "");
  }
}
