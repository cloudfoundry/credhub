package org.cloudfoundry.credhub.utils

import com.jayway.jsonpath.JsonPath
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.springframework.test.web.servlet.MvcResult
import org.springframework.test.web.servlet.ResultMatcher

class MultiJsonPathMatcher {
    companion object {
        @JvmStatic
        fun multiJsonPath(vararg keysAndValues: Any): ResultMatcher =
            ResultMatcher { result: MvcResult ->
                var i = 0
                while (i < keysAndValues.size) {
                    val jsonPath = keysAndValues[i++] as String
                    val expectedValue = keysAndValues[i++]
                    MatcherAssert.assertThat(
                        "field $jsonPath",
                        JsonPath.compile(jsonPath).read(result.response.contentAsString),
                        CoreMatchers.equalTo(expectedValue),
                    )
                }
            }
    }
}
