/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.jxpath;

import java.beans.PropertyDescriptor;
import java.io.Serializable;

/**
 * JXPathBeanInfo  is similar to {@link java.beans.BeanInfo} in that it describes
 * properties of a JavaBean class.  By default, JXPathBeanInfo classes are
 * automatically generated by {@link JXPathIntrospector JXPathIntrospector}
 * based on the java.beans.BeanInfo. As with JavaBeans, the user can supply an
 * alternative implementation of JXPathBeanInfo for a custom class.  The
 * alternative implementation is located by class name, which is the same as the
 * name of the class it represents with the suffix "XBeanInfo".  So, for
 * example, if you need to provide an alternative JXPathBeanInfo class for class
 * "com.foo.Bar", write a class "com.foo.BarXBeanInfo" and make it implement the
 * JXPathBeanInfo interface.
 *
 * @author Dmitri Plotnikov
 */
public interface JXPathBeanInfo extends Serializable {

    /**
     * Returns true if objects of this class are treated as atomic
     * objects which have no properties of their own.
     * For example, {@link String} and {@link Number} are atomic.
     * @return boolean
     */
    boolean isAtomic();

    /**
     * Returns true if the objects of this class have dynamic properties
     * (e.g. java.util.Map). If this method returns true, {@link #getPropertyDescriptors}
     * should return null and {@link #getDynamicPropertyHandlerClass} should return
     * a valid class name.  An object cannot have both static and dynamic
     * properties at the same time.
     * @return boolean
     */
    boolean isDynamic();

    /**
     * Returns a list of property descriptors for the beans described by this
     * bean info object.  Returns null for atomic beans.
     * @return PropertyDescriptor[]
     */
    PropertyDescriptor[] getPropertyDescriptors();

    /**
     * Returns a PropertyDescriptor for the specified name or null if there
     * is no such property.
     * @param propertyName property name
     * @return PropertyDescriptor
     */
    PropertyDescriptor getPropertyDescriptor(String propertyName);

    /**
     * For dynamic objects, returns the class implementing
     * the {@link DynamicPropertyHandler} interface. That class can
     * be used to access dynamic properties.
     * @return Class
     */
    Class getDynamicPropertyHandlerClass();
}
