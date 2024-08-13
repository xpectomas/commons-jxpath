/**
 * @name JXPath CVE
 * @description jxpath cve flow
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id java
 * @tags cve
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module JXPathInjectionTrackingConfig implements DataFlow::ConfigSig{

    predicate isSource(DataFlow::Node source) { 
            source instanceof RemoteFlowSource 
    }

    predicate isSink(DataFlow::Node sink) {
        exists(MethodCall m |
            m.getMethod().hasQualifiedName("org.apache.commons.jxpath", "JXPathContext",
            ["createPath", "createPathAndSetValue", "getPointer", "getValue", "iterate", "iteratePointers", "removeAll", "removePath", "selectNodes", "selectSingleNode", "setValue"]) and 
            m.getArgument(0) = sink.asExpr()
        )
    }
}


module targetFlow = TaintTracking::Global<JXPathInjectionTrackingConfig>;

from DataFlow::Node source, DataFlow::Node sink
where targetFlow::flow(source, sink)
select source, sink, sink.toString()
