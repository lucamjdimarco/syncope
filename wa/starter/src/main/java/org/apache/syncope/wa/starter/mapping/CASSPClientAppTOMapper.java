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
package org.apache.syncope.wa.starter.mapping;

import org.apache.syncope.common.lib.to.CASSPClientAppTO;
import org.apache.syncope.common.lib.to.ClientAppTO;
import org.apache.syncope.common.lib.wa.WAClientApp;
import org.apereo.cas.services.CasRegisteredService;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.RegisteredServiceAccessStrategy;
import org.apereo.cas.services.RegisteredServiceAttributeReleasePolicy;
import org.apereo.cas.services.RegisteredServiceAuthenticationPolicy;
import org.apereo.cas.services.RegisteredServiceMultifactorPolicy;
import org.apereo.cas.services.RegisteredServiceProxyGrantingTicketExpirationPolicy;
import org.apereo.cas.services.RegisteredServiceProxyTicketExpirationPolicy;
import org.apereo.cas.services.RegisteredServiceServiceTicketExpirationPolicy;
import org.apereo.cas.services.RegisteredServiceTicketGrantingTicketExpirationPolicy;
import org.springframework.context.ConfigurableApplicationContext;

public class CASSPClientAppTOMapper extends AbstractClientAppMapper {

    @Override
    public boolean supports(final ClientAppTO clientApp) {
        return CASSPClientAppTO.class.equals(clientApp.getClass());
    }

    @Override
    public RegisteredService map(
            final ConfigurableApplicationContext ctx,
            final WAClientApp clientApp,
            final RegisteredServiceAuthenticationPolicy authPolicy,
            final RegisteredServiceMultifactorPolicy mfaPolicy,
            final RegisteredServiceAccessStrategy accessStrategy,
            final RegisteredServiceAttributeReleasePolicy attributeReleasePolicy,
            final RegisteredServiceTicketGrantingTicketExpirationPolicy tgtExpirationPolicy,
            final RegisteredServiceServiceTicketExpirationPolicy stExpirationPolicy,
            final RegisteredServiceProxyGrantingTicketExpirationPolicy tgtProxyExpirationPolicy,
            final RegisteredServiceProxyTicketExpirationPolicy stProxyExpirationPolicy) {

        CASSPClientAppTO cas = CASSPClientAppTO.class.cast(clientApp.getClientAppTO());

        CasRegisteredService service = new CasRegisteredService();
        service.setServiceId(cas.getServiceId());
        setCommon(service, cas);

        setPolicies(service, authPolicy, mfaPolicy, accessStrategy, attributeReleasePolicy,
                tgtExpirationPolicy, stExpirationPolicy, tgtProxyExpirationPolicy, stProxyExpirationPolicy);

        return service;
    }
}
