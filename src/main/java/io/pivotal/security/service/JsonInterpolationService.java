package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.handler.CredentialHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class JsonInterpolationService {
  private final CredentialHandler credentialHandler;

  @Autowired
  public JsonInterpolationService(CredentialHandler credentialHandler) {
    this.credentialHandler = credentialHandler;
  }

  public Map<String, Object> interpolateCredHubReferences(
      UserContext userContext,
      Map<String, Object> servicesMap,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {

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

        Credential credential = credentialHandler.getMostRecentCredentialVersion(
            credentialName,
            userContext,
            auditRecordParameters
        );

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
