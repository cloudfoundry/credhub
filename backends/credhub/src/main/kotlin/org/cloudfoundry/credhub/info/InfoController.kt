package org.cloudfoundry.credhub.info

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(path = [InfoController.ENDPOINT], produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
class InfoController(@Value("\${auth-server.url:}") val uaaUrl: String) {
    companion object {
        const val ENDPOINT = "/info"
        const val CREHUB_NAME = "CredHub"
    }

    @RequestMapping(method = [RequestMethod.GET], path = [""])
    fun info(): Map<String, Any?> {
        val urlMap = mapOf("url" to uaaUrl)
        val nameMap = mapOf("name" to CREHUB_NAME)
        return mapOf("auth-server" to urlMap, "app" to nameMap)
    }
}
