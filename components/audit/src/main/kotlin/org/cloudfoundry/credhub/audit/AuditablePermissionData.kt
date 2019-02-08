package org.cloudfoundry.credhub.audit

import java.util.UUID

interface AuditablePermissionData {
    var uuid: UUID?
    var path: String?
}
