package org.cloudfoundry.credhub.versions

import org.cloudfoundry.credhub.utils.VersionProvider
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(path = [VersionController.ENDPOINT], produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
class VersionController(val versionProvider: VersionProvider) {
    companion object {
        const val ENDPOINT = "/version"
    }

    @RequestMapping(method = [RequestMethod.GET], path = [""])
    fun version(): Map<String, String> {
        return mapOf("version" to versionProvider.currentVersion())
    }
}