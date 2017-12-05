package org.cloudfoundry.credhub.repository;

import org.cloudfoundry.credhub.entity.AuthFailureAuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthFailureAuditRecordRepository extends
    JpaRepository<AuthFailureAuditRecord, Long> {

}
