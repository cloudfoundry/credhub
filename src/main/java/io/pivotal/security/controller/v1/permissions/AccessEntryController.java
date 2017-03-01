package io.pivotal.security.controller.v1.permissions;

import static io.pivotal.security.controller.v1.permissions.AccessEntryController.API_V1_RESOURCES;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.service.AccessControlService;
import io.pivotal.security.view.AccessEntryResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = API_V1_RESOURCES, produces = MediaType.APPLICATION_JSON_UTF8_VALUE, consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class AccessEntryController {

    public static final String API_V1_RESOURCES = "/api/v1/resources";

    private AccessControlService accessControlService;

    @Autowired
    public AccessEntryController(AccessControlService accessControlService) {
        this.accessControlService = accessControlService;
    }

    @PostMapping(path="/aces")
    public AccessEntryResponse setAccessControlEntry(@Validated @RequestBody AccessEntryRequest accessEntryRequest){
       return accessControlService.setAccessControlEntry(accessEntryRequest);
    }
}
