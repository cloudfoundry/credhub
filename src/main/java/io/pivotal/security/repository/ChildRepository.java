package io.pivotal.security.repository;

import io.pivotal.security.entity.Child;
import io.pivotal.security.entity.Parent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ChildRepository extends JpaRepository<Child, Long> {
//  public Child findByParentId(Long parentId);
  public Child findByParent(Parent parent);


 // public Child findFirst(Specification<Child> specification);
}
