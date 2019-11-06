package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonAutoDetect
import org.cloudfoundry.credhub.PermissionOperation

@JsonAutoDetect
class PermissionsV2PatchRequest {
    var operations: MutableList<PermissionOperation>? = null
}
