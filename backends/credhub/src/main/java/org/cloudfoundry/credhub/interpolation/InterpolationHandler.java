package org.cloudfoundry.credhub.interpolation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.JsonCredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.services.PermissionedCredentialService;

@Service
public class InterpolationHandler {

  private final PermissionedCredentialService credentialService;
  private final CEFAuditRecord auditRecord;

  @Autowired
  public InterpolationHandler(final PermissionedCredentialService credentialService, final CEFAuditRecord auditRecord) {
    super();
    this.credentialService = credentialService;
    this.auditRecord = auditRecord;
  }

  public Map<String, Object> interpolateCredHubReferences(final Map<String, Object> servicesMap) {
    for (final Object serviceProperties : servicesMap.values()) {
      if (!(serviceProperties instanceof ArrayList)) {
        continue;
      }
      for (final Object properties : (ArrayList) serviceProperties) {
        if (!(properties instanceof Map)) {
          continue;
        }
        final Map<String, Object> propertiesMap = (Map) properties;
        final Object credentials = propertiesMap.get("credentials");
        if (!(credentials instanceof Map)) {
          continue;
        }
        // Allow either snake_case or kebab-case
        Object credhubRef = ((Map) credentials).get("credhub_ref");
        if (credhubRef == null) {
          credhubRef = ((Map) credentials).get("credhub-ref");
        }

        if (!(credhubRef instanceof String)) {
          continue;
        }
        final String credentialName = getCredentialNameFromRef((String) credhubRef);

        final List<CredentialVersion> credentialVersions = credentialService
          .findNByName(credentialName, 1);

        if (credentialVersions.isEmpty()) {
          throw new EntryNotFoundException("error.credential.invalid_access");
        }

        final CredentialVersion credentialVersion = credentialVersions.get(0);

        auditRecord.addResource(credentialVersion.getCredential());
        auditRecord.addVersion(credentialVersion);

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

  private String getCredentialNameFromRef(final String credhubRef) {
    return credhubRef.replaceFirst("^\\(\\(", "").replaceFirst("\\)\\)$", "");
  }
}
