package org.cloudfoundry.credhub.services

import java.util.ArrayList
import org.cloudfoundry.credhub.config.AuthorizationConfig
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.event.ContextRefreshedEvent
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component

@Component
class PermissionInitializer @Autowired
constructor(
    private val permissionService: DefaultPermissionService?,
    private val authorizationConfig: AuthorizationConfig?
) {

    @EventListener(ContextRefreshedEvent::class)
    fun seed() {

        if (authorizationConfig?.permissions == null) {
            return
        }

        for (permission in authorizationConfig.permissions!!) {
            val permissionEntries = ArrayList<PermissionEntry>()
            for (actor in permission.actors!!) {
                permissionEntries.add(PermissionEntry(actor, permission.path!!, permission.operations!!))
            }

            permissionService?.savePermissions(permissionEntries)
        }
    }
}
