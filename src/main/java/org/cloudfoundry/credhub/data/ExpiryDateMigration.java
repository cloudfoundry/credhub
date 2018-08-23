package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.repository.CredentialVersionRepository;
import org.cloudfoundry.credhub.util.CertificateReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ExpiryDateMigration {
    private CredentialVersionRepository credentialVersionRepository;

    @Autowired
    public ExpiryDateMigration(CredentialVersionRepository credentialVersionRepository){
        this.credentialVersionRepository = credentialVersionRepository;
    }

    public void migrate(){
        List<CredentialVersionData> data = credentialVersionRepository.findAllVersionsWithNullExpirationDate();

        for(CredentialVersionData version : data){
            if(version instanceof CertificateCredentialVersionData){
                String certificate = ((CertificateCredentialVersionData) version).getCertificate();
                CertificateReader reader = new CertificateReader(certificate);
                ((CertificateCredentialVersionData) version).setExpiryDate(reader.getNotAfter());
            }
        }
        credentialVersionRepository.saveAll(data);
    }
}
