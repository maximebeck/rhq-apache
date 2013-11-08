/*
 * RHQ Management Platform
 * Copyright (C) 2005-2013 Red Hat, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
package org.rhq.plugins.apache;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.File;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.rhq.augeas.AugeasComponent;
import org.rhq.augeas.node.AugeasNode;
import org.rhq.augeas.tree.AugeasTree;
import org.rhq.core.domain.configuration.Configuration;
import org.rhq.core.domain.configuration.ConfigurationUpdateStatus;
import org.rhq.core.domain.configuration.PropertySimple;
import org.rhq.core.domain.configuration.definition.ConfigurationDefinition;
import org.rhq.core.domain.measurement.AvailabilityType;
import org.rhq.core.domain.measurement.DataType;
import org.rhq.core.domain.measurement.MeasurementDataNumeric;
import org.rhq.core.domain.measurement.MeasurementDataTrait;
import org.rhq.core.domain.measurement.MeasurementReport;
import org.rhq.core.domain.measurement.MeasurementScheduleRequest;
import org.rhq.core.domain.resource.CreateResourceStatus;
import org.rhq.core.domain.resource.ResourceType;
import org.rhq.core.pluginapi.configuration.ConfigurationFacet;
import org.rhq.core.pluginapi.configuration.ConfigurationUpdateReport;
import org.rhq.core.pluginapi.inventory.CreateChildResourceFacet;
import org.rhq.core.pluginapi.inventory.CreateResourceReport;
import org.rhq.core.pluginapi.inventory.DeleteResourceFacet;
import org.rhq.core.pluginapi.inventory.InvalidPluginConfigurationException;
import org.rhq.core.pluginapi.inventory.ResourceComponent;
import org.rhq.core.pluginapi.inventory.ResourceContext;
import org.rhq.core.pluginapi.measurement.MeasurementFacet;
import org.rhq.core.pluginapi.util.ResponseTimeConfiguration;
import org.rhq.core.pluginapi.util.ResponseTimeLogParser;
import org.rhq.plugins.apache.mapping.ApacheAugeasMapping;
import org.rhq.plugins.apache.parser.ApacheDirective;
import org.rhq.plugins.apache.parser.ApacheDirectiveTree;
import org.rhq.plugins.apache.util.AugeasNodeSearch;
import org.rhq.plugins.apache.util.AugeasNodeValueUtil;
import org.rhq.plugins.apache.util.ConfigurationTimestamp;
import org.rhq.plugins.apache.util.RuntimeApacheConfiguration;

/**
 * @author Ian Springer
 * @author Lukas Krejci
 * @author Maxime Beck (Remplacement of the SNMP Module with mod_bmx)
 */
public class ApacheVirtualHostServiceComponent implements ResourceComponent<ApacheServerComponent>, MeasurementFacet,
    ConfigurationFacet, DeleteResourceFacet, CreateChildResourceFacet {

    private static final Log LOG = LogFactory.getLog(ApacheVirtualHostServiceComponent.class);

    public static final String URL_CONFIG_PROP = "url";
    public static final String MAIN_SERVER_RESOURCE_KEY = "MainServer";

    public static final String RESPONSE_TIME_LOG_FILE_CONFIG_PROP =
        ResponseTimeConfiguration.RESPONSE_TIME_LOG_FILE_CONFIG_PROP;
    public static final String RESPONSE_TIME_URL_EXCLUDES_CONFIG_PROP =
        ResponseTimeConfiguration.RESPONSE_TIME_URL_EXCLUDES_CONFIG_PROP;
    public static final String RESPONSE_TIME_URL_TRANSFORMS_CONFIG_PROP =
        ResponseTimeConfiguration.RESPONSE_TIME_URL_TRANSFORMS_CONFIG_PROP;

    public static final String SERVER_NAME_CONFIG_PROP = "ServerName";

    /** Multiply by 1/1000 to convert logged response times, which are in microseconds, to milliseconds. */
    private static final double RESPONSE_TIME_LOG_TIME_MULTIPLIER = 0.001;

    private ResourceContext<ApacheServerComponent> resourceContext;
    private URL url;
    private ResponseTimeLogParser logParser;

    private ConfigurationTimestamp lastConfigurationTimeStamp = new ConfigurationTimestamp();
    private int snmpWwwServiceIndex = -1;

    public static final String RESOURCE_TYPE_NAME = "Apache Virtual Host";

    public void start(ResourceContext<ApacheServerComponent> resourceContext) throws Exception {
        this.resourceContext = resourceContext;
        Configuration pluginConfig = this.resourceContext.getPluginConfiguration();
        String url = pluginConfig.getSimple(URL_CONFIG_PROP).getStringValue();
        if (url != null) {
            try {
                this.url = new URL(url);
                if (this.url.getPort() == 0) {
                    throw new InvalidPluginConfigurationException(
                        "The 'url' connection property is invalid - 0 is not a valid port; please change the value to the "
                            + "port this virtual host is listening on. NOTE: If the 'url' property was set this way "
                            + "after autodiscovery, you most likely did not include the port in the ServerName directive for "
                            + "this virtual host in httpd.conf.");
                }
            } catch (MalformedURLException e) {
                throw new Exception("Value of '" + URL_CONFIG_PROP + "' connection property ('" + url
                    + "') is not a valid URL.");
            }
        }

        ResponseTimeConfiguration responseTimeConfig = new ResponseTimeConfiguration(pluginConfig);
        File logFile = responseTimeConfig.getLogFile();
        if (logFile != null) {
            this.logParser = new ResponseTimeLogParser(logFile, RESPONSE_TIME_LOG_TIME_MULTIPLIER);
            this.logParser.setExcludes(responseTimeConfig.getExcludes());
            this.logParser.setTransforms(responseTimeConfig.getTransforms());
        }
    }

    public void stop() {
        this.resourceContext = null;
        this.url = null;
    }

    public AvailabilityType getAvailability() {	  
    	boolean availability = false;
    	
	   	 try {
	   		 URL url = new URL(ApacheServerComponent.getBmxUrl());
	   		 HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
	   		 urlConn.connect();
	   		 
	   		 if(urlConn.getResponseCode() == HttpURLConnection.HTTP_OK)
	   			 availability = true;
	   		 else
	   			 availability = false;
	   	 }catch (ConnectException e) {
	   		LOG.info("The Apache server is down !");
	   	 } catch (MalformedURLException e) {
	   		LOG.error("Malformed URL : " + ApacheServerComponent.getBmxUrl());
	   	 } catch (IOException e) {
	   		 e.printStackTrace();
	   	 }
	   	 
	   	 if(!availability)
	   		 return AvailabilityType.DOWN;
	   	 else
	   		 return AvailabilityType.UP;
    }

    public Configuration loadResourceConfiguration() throws Exception {
        if (!isAugeasEnabled()) {
            throw new IllegalStateException(ApacheServerComponent.CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);
        }

        ApacheServerComponent parent = resourceContext.getParentResourceComponent();

        AugeasComponent comp = getAugeas();
        try {
            AugeasTree tree = comp.getAugeasTree(ApacheServerComponent.AUGEAS_HTTP_MODULE_NAME);
            ConfigurationDefinition resourceConfigDef =
                resourceContext.getResourceType().getResourceConfigurationDefinition();

            ApacheAugeasMapping mapping = new ApacheAugeasMapping(tree);
            return mapping.updateConfiguration(getNode(tree), resourceConfigDef);
        } finally {
            comp.close();
        }
    }

    public void updateResourceConfiguration(ConfigurationUpdateReport report) {
        if (!isAugeasEnabled()) {
            report.setStatus(ConfigurationUpdateStatus.FAILURE);
            report.setErrorMessage(ApacheServerComponent.CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);
            return;
        }

        AugeasComponent comp = getAugeas();
        AugeasTree tree = null;
        try {
            tree = comp.getAugeasTree(ApacheServerComponent.AUGEAS_HTTP_MODULE_NAME);
            ConfigurationDefinition resourceConfigDef =
                resourceContext.getResourceType().getResourceConfigurationDefinition();
            ApacheAugeasMapping mapping = new ApacheAugeasMapping(tree);
            AugeasNode virtHostNode = getNode(tree);
            mapping.updateAugeas(virtHostNode, report.getConfiguration(), resourceConfigDef);
            tree.save();

            report.setStatus(ConfigurationUpdateStatus.SUCCESS);
            LOG.info("Apache configuration was updated");

            finishConfigurationUpdate(report);
        } catch (Exception e) {
            if (tree != null) {
                String message = "Augeas failed to save configuration " + tree.summarizeAugeasError();
                report.setErrorMessage(message);
                LOG.error(message);
            } else {
                report.setErrorMessageFromThrowable(e);
                LOG.error("Augeas failed to save configuration", e);
            }
            report.setStatus(ConfigurationUpdateStatus.FAILURE);
        } finally {
            comp.close();
        }
    }

    public void deleteResource() throws Exception {
        if (!isAugeasEnabled()) {
            throw new IllegalStateException(ApacheServerComponent.CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);
        }

        if (MAIN_SERVER_RESOURCE_KEY.equals(resourceContext.getResourceKey())) {
            throw new IllegalArgumentException(
                "Cannot delete the virtual host representing the main server configuration.");
        }

        AugeasComponent comp = getAugeas();

        try {
            AugeasTree tree = comp.getAugeasTree(ApacheServerComponent.AUGEAS_HTTP_MODULE_NAME);
            AugeasNode myNode = getNode(tree);

            tree.removeNode(myNode, true);
            tree.save();

            deleteEmptyFile(tree, myNode);
            conditionalRestart();
        } catch (IllegalStateException e) {
            //this means we couldn't find the augeas node for this vhost.
            //that error can be safely ignored in this situation.
        } finally {
            comp.close();
        }
    }

    public void getValues(MeasurementReport report, Set<MeasurementScheduleRequest> schedules) throws Exception {    	
    	URL url;
    	URLConnection conn;
    	
    	url = new URL(ApacheServerComponent.getBmxUrl());
        conn = url.openConnection();
        BufferedInputStream in = new BufferedInputStream(conn.getInputStream());       
        Map<String,String> values = ApacheServerComponent.parseInput(in);
        in.close();


         for (MeasurementScheduleRequest req : schedules) {
             String name = req.getName();
             if (values.containsKey(name)) {
                 if (req.getDataType()== DataType.TRAIT) {
                     String val = values.get(name);
                     MeasurementDataTrait mdt = new MeasurementDataTrait(req,val);                     
                     report.addData(mdt);
                 } else {
                    Double val = Double.valueOf(values.get(name));
                    MeasurementDataNumeric mdn = new MeasurementDataNumeric(req,val);
                    report.addData(mdn);
                 }
             }
         }
         
        LOG.info("Collected " + report.getDataCount() + " metrics for VirtualHost "
            + this.resourceContext.getResourceKey() + ".");
    }
    

    public CreateResourceReport createResource(CreateResourceReport report) {
        if (!isAugeasEnabled()) {
            report.setStatus(CreateResourceStatus.FAILURE);
            report.setErrorMessage(ApacheServerComponent.CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);
            return report;
        }

        ResourceType resourceType = report.getResourceType();
        AugeasComponent comp = null;
        try {
            comp = getAugeas();
            if (resourceType.equals(getDirectoryResourceType())) {
                Configuration resourceConfiguration = report.getResourceConfiguration();
                Configuration pluginConfiguration = report.getPluginConfiguration();

                String directoryName = report.getUserSpecifiedResourceName();

                //fill in the plugin configuration

                //get the directive index
                AugeasTree tree = comp.getAugeasTree(ApacheServerComponent.AUGEAS_HTTP_MODULE_NAME);
                AugeasNode myNode = getNode(tree);
                List<AugeasNode> directories = myNode.getChildByLabel("<Directory");
                int seq = 1;
                /*
                 * myNode will be parent node of the new Directory node.
                 * We need to create a new node for directory node which will contain child nodes.
                 * To create a node we can call method from AugeasTree which will create a node. In this method is 
                 * parameter sequence, if we will leave this parameter empty and there will be more nodes with 
                 * the same label, new node will be created but the method createNode will return node with index 0 resp 1.
                 * If that will happen we can not update the node anymore because we are updating wrong node.
                 * To avoid this situation we need to know what is the last sequence nr. of virtual host's child (directory) nodes.
                 * We can not just count child nodes with the same label because some of the child nodes
                 * could be stored in another file. So that in httpd configurationstructure they are child nodes of virtual host,
                 *  but in augeas configuration structure they can be child nodes of node Include[];. 
                 */

                for (AugeasNode n : directories) {
                    String param = n.getFullPath();
                    int end = param.lastIndexOf(File.separatorChar);
                    if (end != -1)
                        if (myNode.getFullPath().equals(param.substring(0, end)))
                            seq++;
                }

                //pluginConfiguration.put(new PropertySimple(ApacheDirectoryComponent.DIRECTIVE_INDEX_PROP, seq));
                //we don't support this yet... need to figure out how...
                pluginConfiguration.put(new PropertySimple(ApacheDirectoryComponent.REGEXP_PROP, false));
                String dirNameToSet = AugeasNodeValueUtil.escape(directoryName);

                //now actually create the data in augeas
                try {
                    ApacheAugeasMapping mapping = new ApacheAugeasMapping(tree);
                    AugeasNode directoryNode = tree.createNode(myNode, "<Directory", null, seq);
                    String myNodeKey = AugeasNodeSearch.getNodeKey(myNode, tree.getRootNode());
                    tree.createNode(directoryNode, "param", dirNameToSet, 0);
                    mapping.updateAugeas(directoryNode, resourceConfiguration,
                        resourceType.getResourceConfigurationDefinition());

                    tree.save();
                    comp.close();
                    tree = comp.getAugeasTree(ApacheServerComponent.AUGEAS_HTTP_MODULE_NAME);

                    AugeasNode parentNode;
                    if (myNodeKey.equals("")) {
                        parentNode = tree.getRootNode();
                    } else
                        parentNode = AugeasNodeSearch.findNodeById(tree.getRootNode(), myNodeKey);

                    List<AugeasNode> nodes = parentNode.getChildByLabel("<Directory");
                    if (nodes.size() < seq) {
                        report.setStatus(CreateResourceStatus.FAILURE);
                        report.setErrorMessage("Could not create directory node.");
                    }

                    AugeasNode nd = nodes.get(seq - 1);
                    String key = AugeasNodeSearch.getNodeKey(nd, parentNode);

                    report.setResourceKey(key);
                    report.setResourceName(directoryName);

                    report.setStatus(CreateResourceStatus.SUCCESS);

                    resourceContext.getParentResourceComponent().finishChildResourceCreate(report);
                } catch (Exception e) {
                    LOG.error("Could not create httpd virtual host child resource.", e);
                    report.setException(e);
                    report.setStatus(CreateResourceStatus.FAILURE);
                }
            } else {
                report.setErrorMessage("Unable to create resources of type " + resourceType.getName());
                report.setStatus(CreateResourceStatus.FAILURE);
            }
        } finally {
            if (comp != null)
                comp.close();
        }
        return report;
    }

    public AugeasComponent getAugeas() {
        return resourceContext.getParentResourceComponent().getAugeas();
    }

    /**
     * Returns a node corresponding to this component in the Augeas tree.
     * 
     * @param tree
     * @return
     * @throws IllegalStateException if none or more than one nodes found
     */
    public AugeasNode getNode(AugeasTree tree) {
        String resourceKey = resourceContext.getResourceKey();

        int snmpIdx = getWwwServiceIndex();

        ApacheServerComponent server = resourceContext.getParentResourceComponent();

        if (snmpIdx < 1) {
            throw new IllegalStateException("Could not determine the index of the virtual host [" + resourceKey
                + "] in the runtime configuration. This is very strange.");
        }

        if (snmpIdx == 1) {
            return tree.getRootNode();
        }

        final List<AugeasNode> allVhosts = new ArrayList<AugeasNode>();

        RuntimeApacheConfiguration.walkRuntimeConfig(new RuntimeApacheConfiguration.NodeVisitor<AugeasNode>() {
            public void visitOrdinaryNode(AugeasNode node) {
                if ("<VirtualHost".equalsIgnoreCase(node.getLabel())) {
                    allVhosts.add(node);
                }
            }

            public void visitConditionalNode(AugeasNode node, boolean isSatisfied) {
            }
        }, tree, server.getCurrentProcessInfo(), server.getCurrentBinaryInfo(), server.getModuleNames(), false);

        //transform the SNMP index into the index of the vhost
        int idx = allVhosts.size() - snmpIdx + 1;

        AugeasNode vhost = allVhosts.get(idx);

        //now check if there are any If* directives underneath this vhost.
        //we don't support configuring such beasts.
        if (vhost.getChildByLabel("<IfDefine").isEmpty() && vhost.getChildByLabel("<IfModule").isEmpty()
            && vhost.getChildByLabel("<IfVersion").isEmpty()) {

            return vhost;
        } else {
            throw new IllegalStateException("Configuration of the virtual host [" + resourceKey
                + "] contains conditional blocks. This is not supported by this plugin.");
        }
    }
    
    /**
     * @see ApacheServerComponent#finishConfigurationUpdate(ConfigurationUpdateReport)
     */
    public void finishConfigurationUpdate(ConfigurationUpdateReport report) {
        resourceContext.getParentResourceComponent().finishConfigurationUpdate(report);
    }

    /**
     * @see ApacheServerComponent#conditionalRestart()
     * 
     * @throws Exception
     */
    public void conditionalRestart() throws Exception {
        resourceContext.getParentResourceComponent().conditionalRestart();
    }

    public void deleteEmptyFile(AugeasTree tree, AugeasNode deletedNode) {
        resourceContext.getParentResourceComponent().deleteEmptyFile(tree, deletedNode);
    }
    
    public static int getWwwServiceIndex(ApacheServerComponent parent, String resourceKey) {
        //figure out the servername and addresses of this virtual host
        //from the resource key.
        String vhostServerName = null;
        String[] vhostAddressStrings = null;
        int pipeIdx = resourceKey.indexOf('|');
        if (pipeIdx >= 0) {
            vhostServerName = resourceKey.substring(0, pipeIdx);
            if (vhostServerName.isEmpty()) {
                vhostServerName = null;
            }
        }
        vhostAddressStrings = resourceKey.substring(pipeIdx + 1).split(" ");

        int foundIdx = 0;

        //only look for the vhost entry if the vhost we're looking for isn't the main server
        if (!MAIN_SERVER_RESOURCE_KEY.equals(vhostAddressStrings[0])) {
            ApacheDirectiveTree tree = parent.parseRuntimeConfiguration(false);

            //find the vhost entry the resource key represents
            List<ApacheDirective> vhosts = tree.search("/<VirtualHost");
            for (ApacheDirective vhost : vhosts) {
                List<ApacheDirective> serverNames = vhost.getChildByName("ServerName");
                String serverName = serverNames.size() > 0 ? serverNames.get(0).getValuesAsString() : null;

                List<String> addrs = vhost.getValues();

                boolean serverNamesMatch =
                    (serverName == null && vhostServerName == null)
                        || (serverName != null && serverName.equals(vhostServerName));
                boolean addrsMatch = true;

                if (addrs.size() != vhostAddressStrings.length) {
                    addrsMatch = false;
                } else {
                    for (int i = 0; i < vhostAddressStrings.length; ++i) {
                        if (!addrs.contains(vhostAddressStrings[i])) {
                            addrsMatch = false;
                            break;
                        }
                    }
                }

                if (serverNamesMatch && addrsMatch) {
                    break;
                }

                ++foundIdx;
            }

            if (foundIdx == vhosts.size()) {
                LOG.debug("The virtual host with resource key [" + resourceKey
                    + "] doesn't seem to be present in the apache configuration anymore.");
                return -1;
            } else {
                //httpd vhosts are internally (in httpd internal data structures) ordered like this:
                //1) the main server entry is always first
                //2) all the vhosts are ordered from the last to appear in the joined config files to the first one

                //we now have an index to the list of the vhosts in the order they are defined.
                //so let's swap it over.
                //just subtracting from the size will give us the "room" for the first index
                //being the main host. In another words the below subtraction is correct even though
                //you might think there's a 1-off bug there.
                foundIdx = vhosts.size() - foundIdx;
            }
        }

        //the snmp indices are 1-based
        return foundIdx + 1;
    }

    /**
     * @return the index of the virtual host that identifies it in SNMP
     * @throws Exception on SNMP error
     */
    
    private int getWwwServiceIndex() {
        ConfigurationTimestamp currentTimestamp =
            resourceContext.getParentResourceComponent().getConfigurationTimestamp();
        if (!lastConfigurationTimeStamp.equals(currentTimestamp)) {
        	snmpWwwServiceIndex = -1;
            //don't go through this configuration again even if we fail further below.. we'd fail again.
            lastConfigurationTimeStamp = currentTimestamp;

            //configuration has changed. re-read the service index of this virtual host            
            snmpWwwServiceIndex =
                getWwwServiceIndex(resourceContext.getParentResourceComponent(), resourceContext.getResourceKey());
        }
        return snmpWwwServiceIndex;
    }

    private ResourceType getDirectoryResourceType() {
        return resourceContext.getResourceType().getChildResourceTypes().iterator().next();
    }

    public boolean isAugeasEnabled() {
        ApacheServerComponent parent = resourceContext.getParentResourceComponent();
        return parent.isAugeasEnabled();
    }

}
