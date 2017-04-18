package io.pivotal.security.data;

import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.repository.EventAuditRecordRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EventAuditRecordDataService {

  private final EventAuditRecordRepository eventAuditRecordRepository;

  @Autowired
  EventAuditRecordDataService(EventAuditRecordRepository eventAuditRecordRepository) {
    this.eventAuditRecordRepository = eventAuditRecordRepository;
  }

  public List<EventAuditRecord> save(List<EventAuditRecord> records) {
    return eventAuditRecordRepository.save(records);
  }
}
