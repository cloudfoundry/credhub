package org.cloudfoundry.credhub

interface ManagementService {
    fun isReadOnlyMode(): Boolean
    fun toggleReadOnlyMode(shouldUseReadOnlyMode: Boolean)
}
