package org.cloudfoundry.credhub.keyusage

import org.springframework.http.HttpStatus.OK
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(path = [KeyUsageController.ENDPOINT], produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
class KeyUsageController(val keyUsageHandler: KeyUsageHandler) {

    companion object {
        const val ENDPOINT = "/api/v1/key-usage"
    }

    @RequestMapping(method = [RequestMethod.GET], path = [""])
    fun getKeyUsage(): ResponseEntity<Map<String, Long>> {

        val keyUsage = keyUsageHandler.getKeyUsage()

        return ResponseEntity(keyUsage, OK)
    }
}
