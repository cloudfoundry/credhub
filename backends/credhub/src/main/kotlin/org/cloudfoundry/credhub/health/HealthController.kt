package org.cloudfoundry.credhub.health

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController

@Deprecated("No longer needed after CredHub 2.2 because we have Spring Actuator")
@RestController
@RequestMapping(path = [HealthController.ENDPOINT])
class HealthController {

    companion object {
        const val ENDPOINT = "/health"
    }

    @RequestMapping(
        method = [RequestMethod.GET],
        path = [""]
    )
    fun getHealthStatus(): ResponseEntity<Map<String, String>> {
        try {
            return ResponseEntity(mapOf("status" to "UP"), HttpStatus.OK)
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
    }
}
