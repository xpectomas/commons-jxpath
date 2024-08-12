import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
class JXPathInjectionTracking extends TaintTracking::Configuration {
JXPathInjectionTracking() { this = "JXPathInjectionTracking" }
override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
override predicate isSink(DataFlow::Node sink) {
exists(MethodAccess ma |
ma.getMethod()
.hasQualifiedName("org.apache.commons.jxpath", "JXPathContext",
["createPath", "createPathAndSetValue", "getPointer", "getValue", "iterate",
"iteratePointers", "removeAll", "removePath", "selectNodes", "selectSingleNode", "setValue"]) and
ma.getArgument(0) = sink.asExpr()
)
}
}
from JXPathInjectionTracking cfg, DataFlow::Node src, DataFlow::Node sink
where cfg.hasFlow(src, sink)
select sink, src, sink, "User-controlled data in XPath expression can lead to RCE."
