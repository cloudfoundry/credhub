package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonProperty
import com.google.common.collect.Lists
import org.cloudfoundry.credhub.domain.CredentialVersion

class DataResponse(
    @get:JsonProperty val data: List<CredentialView>,
) {
    companion object {
        fun fromEntity(models: List<CredentialVersion?>): DataResponse {
            val views: MutableList<CredentialView> = Lists.newArrayList()
            for (model in models) {
                if (model != null) {
                    views.add(CredentialView.fromEntity(model))
                }
            }
            return DataResponse(views)
        }

        fun fromEntity(
            models: List<CredentialVersion?>,
            concatenateCas: Boolean,
        ): DataResponse {
            val views: MutableList<CredentialView> = Lists.newArrayList()
            for (model in models) {
                if (model != null) {
                    views.add(CredentialView.Companion.fromEntity(model, concatenateCas))
                }
            }
            return DataResponse(views)
        }
    }
}
