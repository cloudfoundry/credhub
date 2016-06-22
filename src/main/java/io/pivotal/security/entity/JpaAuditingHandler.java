package io.pivotal.security.entity;

import io.pivotal.security.model.CurrentTimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mapping.PersistentEntity;
import org.springframework.data.mapping.PersistentProperty;
import org.springframework.data.mapping.context.MappingContext;

import javax.annotation.PostConstruct;

public class JpaAuditingHandler extends org.springframework.data.auditing.AuditingHandler {
    @Autowired
    private CurrentTimeProvider currentTimeProvider;

    public JpaAuditingHandler(MappingContext<? extends PersistentEntity<?, ?>, ? extends PersistentProperty<?>> mappingContext) {
        super(mappingContext);
    }

    @PostConstruct
    public void init() {
        setDateTimeProvider(currentTimeProvider);
    }
}