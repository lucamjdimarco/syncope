
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import groovy.transform.CompileStatic
import org.apache.syncope.common.lib.to.Provision
import org.apache.syncope.core.persistence.api.dao.PushCorrelationRule
import org.apache.syncope.core.persistence.api.entity.Any
import org.apache.syncope.core.persistence.api.entity.ExternalResource
import org.identityconnectors.framework.common.objects.AttributeBuilder
import org.identityconnectors.framework.common.objects.filter.Filter
import org.identityconnectors.framework.common.objects.filter.FilterBuilder

/**
 * Test push rule relying on {@code email} attribute value.
 */
@CompileStatic
class TestPushRule implements PushCorrelationRule {

  @Override
  Filter getFilter(final Any<?> any, final ExternalResource resource, final Provision provision) {
    return FilterBuilder.equalTo(
      AttributeBuilder.build("email", any.getPlainAttr("email").get().getValuesAsStrings().get(0)));
  }
}
