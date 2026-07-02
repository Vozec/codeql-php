/**
 * @kind table
 * @id php/test/namespaces
 */
import php

from Class c
select c.getQualifiedName() as fqn,
  concat(c.getASuperType().getQualifiedName(), ", ") as resolvedSuper,
  concat(c.getAMethod().getName(), ", ") as methods
