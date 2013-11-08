/*
 * RHQ Management Platform
 * Copyright (C) 2005-2009 Red Hat, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation, and/or the GNU Lesser
 * General Public License, version 2.1, also as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License and the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package org.rhq.plugins.apache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.rhq.augeas.AugeasComponent;
import org.rhq.augeas.node.AugeasNode;
import org.rhq.augeas.tree.AugeasTree;
import org.rhq.core.domain.configuration.Configuration;
import org.rhq.core.domain.configuration.ConfigurationUpdateStatus;
import org.rhq.core.domain.configuration.definition.ConfigurationDefinition;
import org.rhq.core.domain.measurement.AvailabilityType;
import org.rhq.core.pluginapi.configuration.ConfigurationFacet;
import org.rhq.core.pluginapi.configuration.ConfigurationUpdateReport;
import org.rhq.core.pluginapi.inventory.DeleteResourceFacet;
import org.rhq.core.pluginapi.inventory.InvalidPluginConfigurationException;
import org.rhq.core.pluginapi.inventory.ResourceComponent;
import org.rhq.core.pluginapi.inventory.ResourceContext;
import org.rhq.plugins.apache.mapping.ApacheAugeasMapping;
import org.rhq.plugins.apache.util.AugeasNodeSearch;

public class ApacheIfModuleComponent implements ResourceComponent<ApacheVirtualHostServiceComponent>,
    ConfigurationFacet, DeleteResourceFacet {

    private AugeasTree tree;
    private ResourceContext<ApacheVirtualHostServiceComponent> context;
    private ApacheVirtualHostServiceComponent parentComponent;
    private final Log log = LogFactory.getLog(this.getClass());
    private static final String IFMODULE_DIRECTIVE_NAME = "<IfModule";

    public void start(ResourceContext<ApacheVirtualHostServiceComponent> context)
        throws InvalidPluginConfigurationException, Exception {

        this.context = context;
        parentComponent = context.getParentResourceComponent();
    }

    public void stop() {
    }

    public AvailabilityType getAvailability() {
        return parentComponent.getAvailability();
    }

    public Configuration loadResourceConfiguration() throws Exception {
        if (!isAugeasEnabled()) {
            throw new IllegalStateException(ApacheServerComponent.CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);
        }

        AugeasComponent comp = null;
        try {
            comp = parentComponent.getAugeas();
            AugeasTree tree = comp.getAugeasTree(ApacheServerComponent.AUGEAS_HTTP_MODULE_NAME);
            ConfigurationDefinition resourceConfigDef = context.getResourceType().getResourceConfigurationDefinition();

            AugeasNode virtualHostNode = parentComponent.getNode(tree);
            ApacheAugeasMapping mapping = new ApacheAugeasMapping(tree);
            return mapping.updateConfiguration(getNode(virtualHostNode), resourceConfigDef);
        } finally {
            if (comp != null)
                comp.close();
        }
    }

    public void updateResourceConfiguration(ConfigurationUpdateReport report) {
        if (!isAugeasEnabled()) {
            report.setStatus(ConfigurationUpdateStatus.FAILURE);
            report.setErrorMessage(ApacheServerComponent.CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);
            return;
        }

        AugeasComponent comp = null;
        AugeasTree tree = null;
        try {
            comp = parentComponent.getAugeas();
            tree = comp.getAugeasTree(ApacheServerComponent.AUGEAS_HTTP_MODULE_NAME);
            ConfigurationDefinition resourceConfigDef = context.getResourceType().getResourceConfigurationDefinition();
            ApacheAugeasMapping mapping = new ApacheAugeasMapping(tree);

            AugeasNode directoryNode = getNode(parentComponent.getNode(tree));
            mapping.updateAugeas(directoryNode, report.getConfiguration(), resourceConfigDef);
            tree.save();

            report.setStatus(ConfigurationUpdateStatus.SUCCESS);
            log.info("Apache configuration was updated");

            context.getParentResourceComponent().finishConfigurationUpdate(report);
        } catch (Exception e) {
            if (tree != null)
                log.error("Augeas failed to save configuration " + tree.summarizeAugeasError());
            else
                log.error("Augeas failed to save configuration", e);
            report.setStatus(ConfigurationUpdateStatus.FAILURE);
        } finally {
            if (comp != null)
                comp.close();
        }
    }

    public void deleteResource() throws Exception {

    }

    private AugeasNode getNode(AugeasNode virtualHost) {
        AugeasNode directory = AugeasNodeSearch.findNodeById(virtualHost, context.getResourceKey());
        return directory;
    }

    public boolean isAugeasEnabled() {
        return parentComponent.isAugeasEnabled();
    }

}
