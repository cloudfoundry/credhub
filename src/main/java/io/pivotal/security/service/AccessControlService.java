package io.pivotal.security.service;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.view.AccessEntryResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class AccessControlService {

    private AccessEntryRepository accessEntryRepository;
    private SecretNameRepository secretNameRepository;

    @Autowired
    public AccessControlService(AccessEntryRepository accessEntryRepository,
                                SecretNameRepository secretNameRepository) {
        this.accessEntryRepository = accessEntryRepository;
        this.secretNameRepository = secretNameRepository;
    }

    public AccessEntryResponse setAccessControlEntry(AccessEntryRequest request) {

        SecretName secretName = secretNameRepository.findOneByNameIgnoreCase(request.getCredentialName());
        List<AccessEntryData> accessEntries = accessEntryRepository.findAllByCredentialNameUuid(secretName.getUuid());

        for (AccessControlEntry ace : request.getAccessControlList()) {
            Optional<AccessEntryData> accessEntry = accessEntries.stream()
                    .filter((accessEntryData -> accessEntryData.getActor().equals(ace.getActor())))
                    .findFirst();

            if (accessEntry.isPresent()) {
                for (String operation : ace.getOperations()) {
                    switch (operation) {
                        case "read":
                            accessEntry.get().setReadPermission(true);
                            break;
                        case "write":
                            accessEntry.get().setWritePermission(true);
                            break;
                    }
                }
                accessEntryRepository.saveAndFlush(accessEntry.get());
            } else {
                List<String> operations = ace.getOperations();
                accessEntryRepository.saveAndFlush(new AccessEntryData(secretName,
                        ace.getActor(),
                        operations.contains("read"),
                        operations.contains("write")
                    ));
            }
        }

        List<AccessControlEntry> responseAces = accessEntryRepository.findAllByCredentialNameUuid(secretName.getUuid()).stream().map(this::transformData)
                .collect(Collectors.toList());

        return new AccessEntryResponse(request.getCredentialName(), responseAces);
    }

    private AccessControlEntry transformData(AccessEntryData data) {
        AccessControlEntry entry = new AccessControlEntry();
        List<String> operations = new ArrayList<>();
        if (data.getReadPermission()) {
            operations.add("read");
        }
        if (data.getWritePermission()) {
            operations.add("write");
        }
        entry.setOperations(operations);
        entry.setActor(data.getActor());
        return entry;
    }
}
