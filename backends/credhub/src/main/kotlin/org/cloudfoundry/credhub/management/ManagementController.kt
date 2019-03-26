package org.cloudfoundry.credhub.management

import org.apache.logging.log4j.LogManager
import org.cloudfoundry.credhub.Management
import org.cloudfoundry.credhub.ManagementService
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(
    path = [ManagementController.ENDPOINT],
    produces = [MediaType.APPLICATION_JSON_UTF8_VALUE]
)
class ManagementController(private val managementService: ManagementService) {

    companion object {
        const val ENDPOINT = "/management"
        private val LOGGER = LogManager.getLogger(ManagementController::class.java)
    }

    @RequestMapping(method = [RequestMethod.GET])
    @ResponseStatus(HttpStatus.OK)
    fun isReadOnlyMode(): Management {
        val readOnlyMode = managementService.isReadOnlyMode()

        return Management(readOnlyMode)
    }

    @RequestMapping(
        method = [RequestMethod.POST],
        produces = [MediaType.APPLICATION_JSON_UTF8_VALUE]
    )
    @ResponseStatus(HttpStatus.OK)
    fun updateManagementRegistry(@RequestBody management: Management): Management {

        managementService.toggleReadOnlyMode(management.isReadOnlyMode)

        LOGGER.info("Setting read only mode to " + management.isReadOnlyMode)

        return management
    }
}
