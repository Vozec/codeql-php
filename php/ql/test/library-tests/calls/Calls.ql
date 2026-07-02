/**
 * @kind table
 * @id php/test/calls
 */
import php

query predicate functionCalls(int line, string name, int nargs) {
  exists(FunctionCall c |
    line = c.getLocation().getStartLine() and name = c.getName() and
    nargs = count(int i | exists(c.getArgument(i)))
  )
}

query predicate methodCalls(int line, string method) {
  exists(MethodCall c | line = c.getLocation().getStartLine() and method = c.getMethodName())
}

query predicate staticCalls(int line, string target, string method) {
  exists(StaticMethodCall c |
    line = c.getLocation().getStartLine() and target = c.getTargetName() and method = c.getMethodName()
  )
}

query predicate newExprs(int line, string cls) {
  exists(NewExpr c | line = c.getLocation().getStartLine() and cls = c.getClassName())
}

query predicate concats(int line) {
  exists(ConcatExpr c | line = c.getLocation().getStartLine())
}
