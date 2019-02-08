package org.cloudfoundry.credhub.audit

import java.util.UUID

interface AuditableCredential {
    var uuid: UUID?
    var name: String?
}
