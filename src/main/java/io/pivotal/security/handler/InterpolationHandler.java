package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.JsonCredentialVersion;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class InterpolationHandler {
  private final CredentialsHandler credentialsHandler;

  @Autowired
  public InterpolationHandler(CredentialsHandler credentialsHandler) {
    this.credentialsHandler = credentialsHandler;
  }

  public Map<String, Object> interpolateCredHubReferences(
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

        CredentialVersion credentialVersion = credentialsHandler.getMostRecentCredentialVersion(
            credentialName,
            auditRecordParameters
        );

        if (credentialVersion instanceof JsonCredentialVersion) {
          propertiesMap.put("credentials", ((JsonCredentialVersion) credentialVersion).getValue());
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
