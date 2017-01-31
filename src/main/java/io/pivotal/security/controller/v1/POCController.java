package io.pivotal.security.controller.v1;

import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.entity.Child;
import io.pivotal.security.entity.Parent;
import io.pivotal.security.repository.ChildRepository;
import io.pivotal.security.repository.ParentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;

@Controller
@RequestMapping(path = "/poc", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class POCController {
  private JsonContextFactory jsonContextFactory;
  private ParentRepository parentRepository;
  private ChildRepository childRepository;

  @Autowired
  POCController(
      JsonContextFactory jsonContextFactory,
      ParentRepository parentRepository,
      ChildRepository childRepository
  ) {
    this.jsonContextFactory = jsonContextFactory;
    this.parentRepository = parentRepository;
    this.childRepository = childRepository;
  }

  @RequestMapping(method = RequestMethod.GET, path = "/{name}")
  ResponseEntity getByName(@PathVariable("name") String name, HttpServletRequest request) throws Exception {
    return new ResponseEntity(childRepository.findByParent(parentRepository.findByName(name)), HttpStatus.OK);
//    return new ResponseEntity(childRepository.findByParentId(parentRepository.findByName(name).getId()), HttpStatus.OK);
  }

  @RequestMapping(method = RequestMethod.POST, path = "/{name}")
  ResponseEntity setByName(@PathVariable("name") String name, HttpServletRequest request) throws Exception {
    Parent parent = new Parent();
    parent.setName(name);
    parent = parentRepository.save(parent);
    Child child = new Child();
    child.setFoo("foo");
    child.setParent(parent);
    child = childRepository.save(child);
    return new ResponseEntity(child, HttpStatus.OK);
  }
}
