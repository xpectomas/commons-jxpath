# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
