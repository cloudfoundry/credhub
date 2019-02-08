package org.cloudfoundry.credhub.audit

import java.util.UUID

interface AuditableCredentialVersion {
    var uuid: UUID?
}
