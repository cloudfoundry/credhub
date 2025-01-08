package org.cloudfoundry.credhub.services

import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.data.PermissionDataService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class DefaultPermissionCheckingService
    @Autowired
    constructor(
        private val permissionDataService: PermissionDataService,
        private val userContextHolder: UserContextHolder,
    ) : PermissionCheckingService {
        @Value("\${security.authorization.acls.enabled}")
        private val enforcePermissions: Boolean = false

        override fun hasPermission(
            user: String,
            credentialName: String,
            permission: PermissionOperation,
        ): Boolean {
            if (enforcePermissions) {
                val name = StringUtils.prependIfMissing(credentialName, "/")
                return permissionDataService.hasPermission(user, name, permission)
            }
            return true
        }

        override fun hasPermission(
            user: String,
            permissionGuid: UUID,
            permission: PermissionOperation,
        ): Boolean {
            if (enforcePermissions) {
                val permissionData = permissionDataService.getPermission(permissionGuid) ?: return false
                return permissionDataService.hasPermission(user, permissionData.path!!, permission)
            }
            return true
        }

        override fun hasPermissions(
            user: String,
            path: String,
            permissions: List<PermissionOperation>,
        ): Boolean {
            for (permission in permissions) {
                if (!permissionDataService.hasPermission(user, path, permission)) {
                    return false
                }
            }
            return true
        }

        override fun userAllowedToOperateOnActor(actor: String?): Boolean {
            if (enforcePermissions) {
                val userContext = userContextHolder.userContext
                return actor != null &&
                    userContext?.actor != null &&
                    !StringUtils.equals(userContext.actor, actor)
            } else {
                return true
            }
        }

        override fun userAllowedToOperateOnActor(guid: UUID): Boolean {
            if (enforcePermissions) {
                val userContext = userContextHolder.userContext
                val actor = permissionDataService.getPermission(guid)!!.actor
                return actor != null &&
                    userContext?.actor != null &&
                    !StringUtils.equals(userContext.actor, actor)
            } else {
                return true
            }
        }

        override fun findAllPathsByActor(actor: String): Set<String> = permissionDataService.findAllPathsByActor(actor)
    }
