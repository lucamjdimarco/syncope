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

import java.util.List;
import java.util.Optional;
import org.apache.syncope.common.lib.policy.AttrReleasePolicyTO;
import org.apache.syncope.common.lib.policy.DefaultAttrReleasePolicyConf;
import org.apache.syncope.common.lib.wa.WAClientApp;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.services.DefaultRegisteredServiceAccessStrategy;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.RegisteredServiceAccessStrategy;
import org.apereo.cas.services.RegisteredServiceAttributeReleasePolicy;
import org.apereo.cas.services.RegisteredServiceAuthenticationPolicy;
import org.apereo.cas.services.RegisteredServiceDelegatedAuthenticationPolicy;
import org.apereo.cas.services.RegisteredServiceMultifactorPolicy;
import org.apereo.cas.services.RegisteredServiceProxyGrantingTicketExpirationPolicy;
import org.apereo.cas.services.RegisteredServiceProxyTicketExpirationPolicy;
import org.apereo.cas.services.RegisteredServiceServiceTicketExpirationPolicy;
import org.apereo.cas.services.RegisteredServiceTicketGrantingTicketExpirationPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ConfigurableApplicationContext;

public class RegisteredServiceMapper {

    private static final Logger LOG = LoggerFactory.getLogger(RegisteredServiceMapper.class);

    protected final ConfigurableApplicationContext ctx;

    protected final String pac4jCoreName;

    protected final ObjectProvider<AuthenticationEventExecutionPlan> authEventExecPlan;

    protected final List<AuthMapper> authMappers;

    protected final List<AccessMapper> accessMappers;

    protected final List<AttrReleaseMapper> attrReleaseMappers;

    protected final List<TicketExpirationMapper> ticketExpirationMappers;

    protected final List<ClientAppMapper> clientAppMappers;

    public RegisteredServiceMapper(
            final ConfigurableApplicationContext ctx,
            final String pac4jCoreName,
            final ObjectProvider<AuthenticationEventExecutionPlan> authEventExecPlan,
            final List<AuthMapper> authMappers,
            final List<AccessMapper> accessMappers,
            final List<AttrReleaseMapper> attrReleaseMappers,
            final List<TicketExpirationMapper> ticketExpirationMappers,
            final List<ClientAppMapper> clientAppMappers) {

        this.ctx = ctx;
        this.pac4jCoreName = pac4jCoreName;
        this.authEventExecPlan = authEventExecPlan;
        this.authMappers = authMappers;
        this.accessMappers = accessMappers;
        this.attrReleaseMappers = attrReleaseMappers;
        this.ticketExpirationMappers = ticketExpirationMappers;
        this.clientAppMappers = clientAppMappers;
    }

    public RegisteredService toRegisteredService(final WAClientApp clientApp) {
        ClientAppMapper clientAppMapper = clientAppMappers.stream().
                filter(m -> m.supports(clientApp.getClientAppTO())).
                findFirst().
                orElse(null);
        if (clientAppMapper == null) {
            LOG.warn("Unable to locate ClientAppMapper for {}", clientApp.getClientAppTO().getClass().getName());
            return null;
        }

        RegisteredServiceAuthenticationPolicy authPolicy = null;
        RegisteredServiceMultifactorPolicy mfaPolicy = null;
        RegisteredServiceDelegatedAuthenticationPolicy delegatedAuthPolicy = null;
        if (clientApp.getAuthPolicy() != null) {
            Optional<AuthMapper> authMapper = authMappers.stream().
                    filter(m -> m.supports(clientApp.getAuthPolicy().getConf())).
                    findFirst();
            AuthMapperResult result = authMapper.map(mapper -> mapper.build(
                    ctx, pac4jCoreName, authEventExecPlan, clientApp.getAuthPolicy(), clientApp.getAuthModules())).
                    orElse(AuthMapperResult.EMPTY);
            authPolicy = result.getAuthPolicy();
            mfaPolicy = result.getMfaPolicy();
            delegatedAuthPolicy = result.getDelegateAuthPolicy();
        }

        RegisteredServiceAccessStrategy accessStrategy = null;
        if (clientApp.getAccessPolicy() != null) {
            Optional<AccessMapper> accessMapper = accessMappers.stream().
                    filter(m -> m.supports(clientApp.getAccessPolicy().getConf())).
                    findFirst();
            accessStrategy = accessMapper.map(mapper -> mapper.build(clientApp.getAccessPolicy())).orElse(null);
        }
        if (delegatedAuthPolicy != null) {
            if (accessStrategy == null) {
                accessStrategy = new DefaultRegisteredServiceAccessStrategy();
            }
            if (accessStrategy instanceof DefaultRegisteredServiceAccessStrategy) {
                ((DefaultRegisteredServiceAccessStrategy) accessStrategy).
                        setDelegatedAuthenticationPolicy(delegatedAuthPolicy);
            } else {
                LOG.warn("Could not set delegated auth policy because access strategy is instance of {}",
                        accessStrategy.getClass().getName());
            }
        }

        AttrReleasePolicyTO attrReleasePolicyTO = Optional.ofNullable(clientApp.getAttrReleasePolicy()).
                orElseGet(() -> {
                    AttrReleasePolicyTO arpTO = new AttrReleasePolicyTO();
                    arpTO.setConf(new DefaultAttrReleasePolicyConf());
                    return arpTO;
                });
        Optional<AttrReleaseMapper> attrReleaseMapper = attrReleaseMappers.stream().
                filter(m -> m.supports(attrReleasePolicyTO.getConf())).
                findFirst();
        RegisteredServiceAttributeReleasePolicy attributeReleasePolicy =
                attrReleaseMapper.map(mapper -> mapper.build(attrReleasePolicyTO)).orElse(null);

        RegisteredServiceTicketGrantingTicketExpirationPolicy tgtExpirationPolicy = null;
        RegisteredServiceServiceTicketExpirationPolicy stExpirationPolicy = null;
        RegisteredServiceProxyGrantingTicketExpirationPolicy tgtProxyExpirationPolicy = null;
        RegisteredServiceProxyTicketExpirationPolicy stProxyExpirationPolicy = null;
        if (clientApp.getTicketExpirationPolicy() != null) {
            TicketExpirationMapper ticketExpirationMapper = ticketExpirationMappers.stream().
                    filter(m -> m.supports(clientApp.getTicketExpirationPolicy().getConf())).
                    findFirst().orElse(null);
            if (ticketExpirationMapper != null) {
                tgtExpirationPolicy = ticketExpirationMapper.buildTGT(clientApp.getTicketExpirationPolicy());
                stExpirationPolicy = ticketExpirationMapper.buildST(clientApp.getTicketExpirationPolicy());
                tgtProxyExpirationPolicy = ticketExpirationMapper.buildProxyTGT(clientApp.getTicketExpirationPolicy());
                stProxyExpirationPolicy = ticketExpirationMapper.buildProxyST(clientApp.getTicketExpirationPolicy());
            }
        }

        return clientAppMapper.map(
                ctx,
                clientApp,
                authPolicy,
                mfaPolicy,
                accessStrategy,
                attributeReleasePolicy,
                tgtExpirationPolicy,
                stExpirationPolicy,
                tgtProxyExpirationPolicy,
                stProxyExpirationPolicy);
    }
}
