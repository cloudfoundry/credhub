package org.cloudfoundry.credhub.utils

import com.google.common.io.Resources
import org.springframework.stereotype.Component
import kotlin.text.Charsets.UTF_8

@Component
class ResourceReader {
    fun readFileToString(fileName: String): String {
        val resource = Resources.getResource(fileName)
        return Resources.toString(resource, UTF_8)
    }
}
