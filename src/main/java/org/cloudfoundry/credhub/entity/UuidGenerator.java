package org.cloudfoundry.credhub.entity;

import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SessionImplementor;
import org.hibernate.id.UUIDGenerator;

import java.io.Serializable;

@SuppressWarnings("unused")
public class UuidGenerator extends UUIDGenerator {
  @Override
  public Serializable generate(SessionImplementor session, Object object) throws HibernateException {
    Serializable uuid = session.getEntityPersister(null, object)
        .getClassMetadata().getIdentifier(object, session);

    return uuid != null ? uuid : super.generate(session, object);
  }
}
