package io.pivotal.security.controller.v1.permissions;

import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.service.AccessControlService;
import io.pivotal.security.view.AccessEntryResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccessEntryController {

    private AccessControlService accessControlService;

    @Autowired
    public AccessEntryController(AccessControlService accessControlService) {
        this.accessControlService = accessControlService;
    }

    @PostMapping(path="/api/v1/resources/aces", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public AccessEntryResponse setAccessControlEntry(@Validated @RequestBody AccessEntryRequest accessEntryRequest){

       return accessControlService.setAccessControlEntry(accessEntryRequest);
    }
}
