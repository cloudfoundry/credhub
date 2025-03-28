package org.cloudfoundry.credhub.entities;

import java.io.Serializable;

import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.id.UUIDGenerator;

@SuppressWarnings("unused")
public class UuidGenerator extends UUIDGenerator {
  @Override
  public Serializable generate(final SharedSessionContractImplementor session, final Object object) throws HibernateException {
    final Serializable uuid = (Serializable) session.getEntityPersister(null, object)
      .getClassMetadata().getIdentifier(object, session);

    return uuid != null ? uuid : (Serializable) super.generate(session, object);
  }
}
