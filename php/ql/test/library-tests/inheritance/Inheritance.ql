/**
 * @kind table
 * @id php/test/inheritance
 */
import php

from ClassLike t
select t.getName() as type,
  concat(t.getAnAncestor().getName(), ", ") as ancestors,
  concat(t.getATransitivelyUsedTrait().getName(), ", ") as traits,
  concat(t.getAMethod().getName(), ", ") as methods
