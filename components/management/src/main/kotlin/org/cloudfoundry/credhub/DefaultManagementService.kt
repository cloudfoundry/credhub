package org.cloudfoundry.credhub

class DefaultManagementService(
    val managementRegistry: ManagementRegistry,
) : ManagementService {
    override fun isReadOnlyMode(): Boolean = managementRegistry.readOnlyMode

    override fun toggleReadOnlyMode(shouldUseReadOnlyMode: Boolean) {
        managementRegistry.readOnlyMode = shouldUseReadOnlyMode
    }
}
