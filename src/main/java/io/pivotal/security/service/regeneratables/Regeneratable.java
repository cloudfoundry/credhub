package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.service.AuditRecordBuilder;
import org.springframework.http.ResponseEntity;

public interface Regeneratable {

  ResponseEntity regenerate(NamedSecret secret, AuditRecordBuilder auditRecordBuilder);

}
