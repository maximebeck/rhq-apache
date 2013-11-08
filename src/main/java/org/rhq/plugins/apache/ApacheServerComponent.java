/*
 * RHQ Management Platform
 * Copyright (C) 2005-2012 Red Hat, Inc.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
package org.rhq.plugins.apache;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import net.augeas.Augeas;
import net.augeas.AugeasException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import org.rhq.augeas.AugeasComponent;
import org.rhq.augeas.config.AugeasConfiguration;
import org.rhq.augeas.config.AugeasModuleConfig;
import org.rhq.augeas.node.AugeasNode;
import org.rhq.augeas.tree.AugeasTree;
import org.rhq.augeas.tree.AugeasTreeBuilder;
import org.rhq.augeas.tree.AugeasTreeException;
import org.rhq.augeas.util.Glob;
import org.rhq.core.domain.configuration.Configuration;
import org.rhq.core.domain.configuration.ConfigurationUpdateStatus;
import org.rhq.core.domain.configuration.PropertyList;
import org.rhq.core.domain.configuration.PropertyMap;
import org.rhq.core.domain.configuration.Property;
import org.rhq.core.domain.configuration.PropertySimple;
import org.rhq.core.domain.configuration.definition.ConfigurationDefinition;
import org.rhq.core.domain.event.EventSeverity;
import org.rhq.core.domain.measurement.AvailabilityType;
import org.rhq.core.domain.measurement.DataType;
import org.rhq.core.domain.measurement.MeasurementDataNumeric;
import org.rhq.core.domain.measurement.MeasurementDataTrait;
import org.rhq.core.domain.measurement.MeasurementReport;
import org.rhq.core.domain.measurement.MeasurementScheduleRequest;
import org.rhq.core.domain.resource.CreateResourceStatus;
import org.rhq.core.pluginapi.configuration.ConfigurationFacet;
import org.rhq.core.pluginapi.configuration.ConfigurationUpdateReport;
import org.rhq.core.pluginapi.event.EventContext;
import org.rhq.core.pluginapi.event.EventPoller;
import org.rhq.core.pluginapi.event.log.LogFileEventPoller;
import org.rhq.core.pluginapi.inventory.CreateChildResourceFacet;
import org.rhq.core.pluginapi.inventory.CreateResourceReport;
import org.rhq.core.pluginapi.inventory.InvalidPluginConfigurationException;
import org.rhq.core.pluginapi.inventory.ResourceComponent;
import org.rhq.core.pluginapi.inventory.ResourceContext;
import org.rhq.core.pluginapi.measurement.MeasurementFacet;
import org.rhq.core.pluginapi.operation.OperationFacet;
import org.rhq.core.pluginapi.operation.OperationResult;
import org.rhq.core.system.OperatingSystemType;
import org.rhq.core.system.ProcessInfo;
import org.rhq.core.system.SystemInfo;
import org.rhq.plugins.apache.augeas.ApacheAugeasNode;
import org.rhq.plugins.apache.augeas.AugeasConfigurationApache;
import org.rhq.plugins.apache.augeas.AugeasTreeBuilderApache;
import org.rhq.plugins.apache.mapping.ApacheAugeasMapping;
import org.rhq.plugins.apache.parser.ApacheDirective;
import org.rhq.plugins.apache.parser.ApacheDirectiveTree;
import org.rhq.plugins.apache.util.ApacheBinaryInfo;
import org.rhq.plugins.apache.util.ConfigurationTimestamp;
import org.rhq.plugins.apache.util.HttpdAddressUtility;
import org.rhq.plugins.platform.PlatformComponent;
import org.rhq.rhqtransform.AugeasRHQComponent;

/**
 * The resource component for Apache 2.x servers.
 *
 * @author Ian Springer
 * @author Lukas Krejci
 * @author Maxime Beck (Remplacement of the SNMP Module with mod_bmx)
 */
public class ApacheServerComponent implements AugeasRHQComponent, ResourceComponent<PlatformComponent>,
    MeasurementFacet, OperationFacet, ConfigurationFacet, CreateChildResourceFacet {

    public static final String CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE =
        "Configuration and child resource creation/deletion support for Apache is optional. "
            + "If you switched it on by enabling Augeas support in the connection settings of the Apache server resource and still get this message, "
            + "it means that either your Apache version is not supported (only Apache 2.x is supported) or Augeas is not available on your platform.";

    private final Log log = LogFactory.getLog(this.getClass());

    public static final String PLUGIN_CONFIG_PROP_SERVER_ROOT = "serverRoot";
    public static final String PLUGIN_CONFIG_PROP_EXECUTABLE_PATH = "executablePath";
    public static final String PLUGIN_CONFIG_PROP_CONTROL_SCRIPT_PATH = "controlScriptPath";
    public static final String PLUGIN_CONFIG_PROP_URL = "url";
    public static final String PLUGIN_CONFIG_PROP_HTTPD_CONF = "configFile";
    public static final String AUGEAS_HTTP_MODULE_NAME = "Httpd";

    public static final String PLUGIN_CONFIG_PROP_ERROR_LOG_FILE_PATH = "errorLogFilePath";
    public static final String PLUGIN_CONFIG_PROP_ERROR_LOG_EVENTS_ENABLED = "errorLogEventsEnabled";
    public static final String PLUGIN_CONFIG_PROP_ERROR_LOG_MINIMUM_SEVERITY = "errorLogMinimumSeverity";
    public static final String PLUGIN_CONFIG_PROP_ERROR_LOG_INCLUDES_PATTERN = "errorLogIncludesPattern";
    public static final String PLUGIN_CONFIG_PROP_VHOST_FILES_MASK = "vhostFilesMask";
    public static final String PLUGIN_CONFIG_PROP_VHOST_CREATION_POLICY = "vhostCreationPolicy";

    public static final String PLUGIN_CONFIG_PROP_RESTART_AFTER_CONFIG_UPDATE = "restartAfterConfigurationUpdate";

    public static final String PLUGIN_CONFIG_VHOST_IN_SINGLE_FILE_PROP_VALUE = "single-file";
    public static final String PLUGIN_CONFIG_VHOST_PER_FILE_PROP_VALUE = "vhost-per-file";

    public static final String PLUGIN_CONFIG_CUSTOM_MODULE_NAMES = "customModuleNames";
    public static final String PLUGIN_CONFIG_MODULE_MAPPING = "moduleMapping";
    public static final String PLUGIN_CONFIG_MODULE_NAME = "moduleName";
    public static final String PLUGIN_CONFIG_MODULE_SOURCE_FILE = "moduleSourceFile";

    public static final String AUXILIARY_INDEX_PROP = "_index";

    public static final String SERVER_BUILT_TRAIT = "serverBuilt";
    public static final String AUGEAS_ENABLED = "augeasEnabled";

    public static final String DEFAULT_EXECUTABLE_PATH = "bin" + File.separator
        + ((File.separatorChar == '/') ? "httpd" : "Apache.exe");

    public static final String DEFAULT_ERROR_LOG_PATH = "logs" + File.separator
        + ((File.separatorChar == '/') ? "error_log" : "error.log");

    private static final String ERROR_LOG_ENTRY_EVENT_TYPE = "errorLogEntry";

    private static final String[] CONTROL_SCRIPT_PATHS = { "bin/apachectl", "sbin/apachectl", "bin/apachectl2",
        "sbin/apachectl2" };

    private static final String DEFAULT_BMX_HANDLER_URL = "http://localhost:8000/bmx";

    private static String bmxUrl;
    private static String vHost;
    static Pattern typePattern = Pattern.compile(".*Type=([\\w-]+),.*");
    
    private ResourceContext<PlatformComponent> resourceContext;
    private EventContext eventContext;
    private URL url;
    private ApacheBinaryInfo binaryInfo;
    
    private Map<String, String> moduleNames;

    /**
     * Delegate instance for handling all calls to invoke operations on this component.
     */
    private ApacheServerOperationsDelegate operationsDelegate;

    public void start(ResourceContext<PlatformComponent> resourceContext) throws Exception {      
        log.info("Initializing Resource component for Apache Server [" + resourceContext.getResourceKey() + "]...");

        this.resourceContext = resourceContext;
        this.eventContext = resourceContext.getEventContext();

        boolean configured = false;
        
        Configuration pluginConfig = this.resourceContext.getPluginConfiguration();
        String url = pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_URL, null);
        bmxUrl = pluginConfig.getSimpleValue("bmxUrl", DEFAULT_BMX_HANDLER_URL);
        vHost = pluginConfig.getSimpleValue("vhost","");        
        
        if (url != null) {
            try {
                this.url = new URL(url);
                if (this.url.getPort() == 0) {
                    log.error("The 'url' connection property is invalid - 0 is not a valid port; please change the value to the "
                        + "port the \"main\" Apache server is listening on. NOTE: If the 'url' property was set this way "
                        + "after autodiscovery, you most likely did not include the port in the ServerName directive for "
                        + "the \"main\" Apache server in httpd.conf.");
                } else {
                    configured = true;
                }
            } catch (MalformedURLException e) {
                throw new InvalidPluginConfigurationException("Value of '" + PLUGIN_CONFIG_PROP_URL
                    + "' connection property ('" + url + "') is not a valid URL.");
            }
        } 
                
        if (!configured) {
        	log.info("Availability will be check using BMX");
        }
        
        File executablePath = getExecutablePath();
        try {
            this.binaryInfo =
                ApacheBinaryInfo.getInfo(executablePath.getPath(), this.resourceContext.getSystemInformation());
        } catch (Exception e) {
            throw new InvalidPluginConfigurationException("'" + executablePath
                + "' is not a valid Apache executable (" + e + ").");
        }

        this.operationsDelegate =
            new ApacheServerOperationsDelegate(this, pluginConfig, this.resourceContext.getSystemInformation());

        //init the module names with the defaults
        moduleNames =
            new HashMap<String, String>(ApacheServerDiscoveryComponent.getDefaultModuleNames(binaryInfo
                .getVersion()));

        //and add the user-provided overrides/additions
        PropertyList list = resourceContext.getPluginConfiguration().getList(PLUGIN_CONFIG_CUSTOM_MODULE_NAMES);

        if (list != null) {
            for (Property p : list.getList()) {
                PropertyMap map = (PropertyMap) p;
                String sourceFile = map.getSimpleValue(PLUGIN_CONFIG_MODULE_SOURCE_FILE, null);
                String moduleName = map.getSimpleValue(PLUGIN_CONFIG_MODULE_NAME, null);

                if (sourceFile == null || moduleName == null) {
                    log.info("A corrupted module name mapping found (" + sourceFile + " = " + moduleName
                        + "). Check your module mappings in the plugin configuration for the server: "
                        + resourceContext.getResourceKey());
                    continue;
                }

                moduleNames.put(sourceFile, moduleName);
            }
        }

        startEventPollers();        
    }

    public void stop() {
    	this.url = null;
        stopEventPollers();
    }

    public static String getBmxUrl() {
        return bmxUrl;
    }
    
    public AvailabilityType getAvailability() {
    	boolean availability = false;
    	
    	 try {
    		 URL url = new URL(bmxUrl);
    		 HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
    		 urlConn.connect();
    		 
    		 if(urlConn.getResponseCode() == HttpURLConnection.HTTP_OK)
    			 availability = true;
    		 else
    			 availability = false;
    	 }catch (ConnectException e) {
    		 log.info("The Apache server is down !"); 
    	 } catch (MalformedURLException e) {
    		 log.error("Malformed URL : " + bmxUrl);
    	 } catch (IOException e) {
    		 e.printStackTrace();
    	 }
    	 
    	 if(!availability)
    		 return AvailabilityType.DOWN;
    	 else
    		 return AvailabilityType.UP;
    }

    public void getValues(MeasurementReport report, Set<MeasurementScheduleRequest> metrics) throws Exception {
    	// TODO do some clever caching of data here, so that we won't hammer mod_bmx
        URL url = new URL(bmxUrl);
        URLConnection conn = url.openConnection();
        BufferedInputStream in = new BufferedInputStream(conn.getInputStream());
        Map<String,String> values = parseInput(in);
        in.close();


         for (MeasurementScheduleRequest req : metrics) {
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
    }
    
    public static Map<String, String> parseInput(BufferedInputStream in) throws Exception {
        Map<String,String> ret = new HashMap<String, String>();

        BufferedReader reader = new BufferedReader(new InputStreamReader(in));

        String line;

        while ((line = reader.readLine())!=null) {

            if (!line.startsWith("Name: mod_bmx_"))
                continue;

            // Skip over sample data - this is no real module
            if (line.contains("mod_bmx_example"))
                continue;

            // Now we have a modules output

            // check for the status module
            if (line.contains("mod_bmx_status")) {
                slurpSection(ret,reader,"global");
                continue;
            }


            // If the section does not match our vhost, ignore it.
            if (!line.contains("Host="+vHost))
                continue;

            // Now some global data
            Matcher m = typePattern.matcher(line);

            if (m.matches()) {
                String type = m.group(1);
                if (type.contains("-"))
                    type= type.substring(type.indexOf("-")+1);

                slurpSection(ret, reader, type);
            }
        }

        return ret;
    }
    
    public static void slurpSection(Map<String, String> ret, BufferedReader reader, String type) throws IOException {
        String line;
        while (!(line = reader.readLine()).equals("")) {
            int pos = line.indexOf(":");
            String key = line.substring(0,pos);
            String val = line.substring(pos+2);
            ret.put(type + ":" + key , val);
        }
    }    

    @Nullable
    public OperationResult invokeOperation(@NotNull String name, @NotNull Configuration params) throws Exception {
        log.info("Invoking operation [" + name + "] on server [" + this.resourceContext.getResourceKey() + "]...");
        return this.operationsDelegate.invokeOperation(name, params);
    }

    public Configuration loadResourceConfiguration() throws Exception {

        if (!isAugeasEnabled())
            throw new IllegalStateException(CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);

        AugeasComponent comp = getAugeas();
        try {
            ConfigurationDefinition resourceConfigDef =
                resourceContext.getResourceType().getResourceConfigurationDefinition();

            AugeasTree tree = comp.getAugeasTree(AUGEAS_HTTP_MODULE_NAME);
            ApacheAugeasMapping mapping = new ApacheAugeasMapping(tree);
            return mapping.updateConfiguration(tree.getRootNode(), resourceConfigDef);
        } catch (Exception e) {
            log.error("Failed to load Apache configuration.", e);
            throw e;
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

        Configuration originalConfig = report.getConfiguration().deepCopy(true);
        AugeasTree tree = null;
        try {
            tree = comp.getAugeasTree(AUGEAS_HTTP_MODULE_NAME);
            ConfigurationDefinition resourceConfigDef =
                resourceContext.getResourceType().getResourceConfigurationDefinition();
            ApacheAugeasMapping mapping = new ApacheAugeasMapping(tree);

            mapping.updateAugeas(tree.getRootNode(), report.getConfiguration(), resourceConfigDef);
            tree.save();

            log.info("Apache configuration was updated");
            report.setStatus(ConfigurationUpdateStatus.SUCCESS);

            finishConfigurationUpdate(report);
        } catch (Exception e) {
            if (tree != null) {
                log.error("Augeas failed to save configuration " + tree.summarizeAugeasError());
                e = new AugeasException("Failed to save configuration: " + tree.summarizeAugeasError() + " ", e);
            } else
                log.error("Augeas failed to save configuration", e);
            report.setStatus(ConfigurationUpdateStatus.FAILURE);
            report.setErrorMessageFromThrowable(e);
            if (!originalConfig.equals(report.getConfiguration())) {
                log.error("Configuration has changed");
            } else {
                log.error("Configuratio has not changed");
            }
        } finally {
            comp.close();
        }
    }

    public AugeasComponent getAugeas() throws AugeasTreeException {
        return new AugeasComponent() {

            @Override
            public AugeasConfiguration initConfiguration() {
                File tempDir = resourceContext.getDataDirectory();
                if (!tempDir.exists())
                    throw new RuntimeException("Loading of lens failed");
                AugeasConfigurationApache config =
                    new AugeasConfigurationApache(tempDir.getAbsolutePath(), resourceContext.getPluginConfiguration());
                return config;
            }

            @Override
            public AugeasTreeBuilder initTreeBuilder() {
                AugeasTreeBuilderApache builder = new AugeasTreeBuilderApache();
                return builder;
            }

        };
    }

    public CreateResourceReport createResource(CreateResourceReport report) {
        if (!isAugeasEnabled()) {
            report.setStatus(CreateResourceStatus.FAILURE);
            report.setErrorMessage(CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);
            return report;
        }

        if (ApacheVirtualHostServiceComponent.RESOURCE_TYPE_NAME.equals(report.getResourceType().getName())) {
            Configuration vhostResourceConfig = report.getResourceConfiguration();
            ConfigurationDefinition vhostResourceConfigDef =
                report.getResourceType().getResourceConfigurationDefinition();
            Configuration vhostPluginConfig = report.getPluginConfiguration();

            String vhostDef = report.getUserSpecifiedResourceName();
            String serverName =
                vhostResourceConfig.getSimpleValue(ApacheVirtualHostServiceComponent.SERVER_NAME_CONFIG_PROP, null);

            //determine the resource key
            String resourceKey = vhostDef;
            if (serverName != null) {
                resourceKey = serverName + "|" + resourceKey;
            }

            String[] vhostDefs = vhostDef.split(" ");
            HttpdAddressUtility.Address addr;
            try {
                ApacheDirectiveTree parserTree = parseRuntimeConfiguration(true);

                Pattern virtualHostPattern = Pattern.compile(".+:([\\d]+|\\*)");
                Matcher matcher = virtualHostPattern.matcher(vhostDefs[0]);
                if (!matcher.matches())
                    throw new Exception("Wrong format of virtual host resource name. The right format is Address:Port.");

                addr = getAddressUtility().getVirtualHostSampleAddress(parserTree, vhostDefs[0], serverName, false);
            } catch (Exception e) {
                report.setStatus(CreateResourceStatus.FAILURE);
                report.setErrorMessage("Wrong format of virtual host resource name.");
                report.setException(e);
                return report;
            }

            String resourceName;
            if (serverName != null) {
                resourceName = addr.host + ":" + addr.port;
            } else {
                resourceName = resourceKey;
            }

            report.setResourceKey(resourceKey);
            report.setResourceName(resourceName);

            AugeasComponent comp = getAugeas();
            //determine the resource name

            AugeasTree tree;
            try {

                tree = comp.getAugeasTree(AUGEAS_HTTP_MODULE_NAME);
                //fill in the plugin config
                String url = "http://" + addr.host + ":" + addr.port + "/";
                vhostPluginConfig.put(new PropertySimple(ApacheVirtualHostServiceComponent.URL_CONFIG_PROP, url));

                //determine the sequence number of the new vhost
                List<AugeasNode> existingVhosts = tree.matchRelative(tree.getRootNode(), "<VirtualHost");
                int seq = existingVhosts.size() + 1;

                Configuration pluginConfig = resourceContext.getPluginConfiguration();
                String creationType =
                    pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_VHOST_CREATION_POLICY,
                        PLUGIN_CONFIG_VHOST_PER_FILE_PROP_VALUE);

                AugeasNode vhost = null;

                String vhostFile = comp.getConfiguration().getModules().get(0).getConfigFiles().get(0);

                if (PLUGIN_CONFIG_VHOST_IN_SINGLE_FILE_PROP_VALUE.equals(creationType)) {
                    vhost = tree.createNode(tree.getRootNode(), "<VirtualHost", null, seq);
                } else if (PLUGIN_CONFIG_VHOST_PER_FILE_PROP_VALUE.equals(creationType)) {
                    String mask = pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_VHOST_FILES_MASK, null);
                    if (mask == null) {
                        report.setErrorMessage("No virtual host file mask configured.");
                    } else {
                        vhostFile = getNewVhostFileName(addr, mask);
                        File vhostFileFile = new File(vhostFile);

                        //we're creating a new file here, so we must ensure that Augeas does have this file
                        //on its load path, otherwise it will refuse to create it.
                        AugeasConfigurationApache config = (AugeasConfigurationApache) comp.getConfiguration();
                        AugeasModuleConfig moduleConfig = config.getModuleByName(config.getAugeasModuleName());
                        boolean willPersist = false;
                        for (String glob : moduleConfig.getIncludedGlobs()) {
                            if (Glob.matches(getServerRoot(), glob, vhostFileFile)) {
                                willPersist = true;
                                break;
                            }
                        }

                        if (!willPersist) {
                            //the file wouldn't be loaded by augeas
                            moduleConfig.addIncludedGlob(vhostFile);
                            //this also means that there was no include
                            //that would load the file, so we have to
                            //add the include directive to the main conf.
                            List<AugeasNode> includes = tree.matchRelative(tree.getRootNode(), "Include");
                            AugeasNode include =
                                tree.createNode(tree.getRootNode(), "Include", null, includes.size() + 1);
                            tree.createNode(include, "param", vhostFile, 0);
                            tree.save();
                        }

                        try {
                            vhostFileFile.createNewFile();
                        } catch (IOException e) {
                            log.error("Failed to create a new vhost file: " + vhostFile, e);
                        }

                        comp.close();
                        comp = getAugeas();
                        tree = comp.getAugeasTree(moduleConfig.getModuletName());

                        vhost = tree.createNode(AugeasTree.AUGEAS_DATA_PATH + vhostFile + "/<VirtualHost");
                        ((ApacheAugeasNode) vhost).setParentNode(tree.getRootNode());

                    }
                }

                if (vhost == null) {
                    report.setStatus(CreateResourceStatus.FAILURE);
                } else {
                    try {
                        for (int i = 0; i < vhostDefs.length; ++i) {
                            tree.createNode(vhost, "param", vhostDefs[i], i + 1);
                        }
                        ApacheAugeasMapping mapping = new ApacheAugeasMapping(tree);
                        mapping.updateAugeas(vhost, vhostResourceConfig, vhostResourceConfigDef);

                        tree.save();
                        report.setStatus(CreateResourceStatus.SUCCESS);

                        finishChildResourceCreate(report);
                    } catch (Exception e) {
                        report.setStatus(CreateResourceStatus.FAILURE);
                        report.setException(e);
                    }
                }
            } finally {
                if (comp != null)
                    comp.close();
            }
        }

        return report;
    }

    /**
     * Return the absolute path of this Apache server's server root (e.g. "C:\Program Files\Apache Group\Apache2").
     *
     * @return the absolute path of this Apache server's server root (e.g. "C:\Program Files\Apache Group\Apache2")
     */
    @NotNull
    public File getServerRoot() {
        Configuration pluginConfig = this.resourceContext.getPluginConfiguration();
        String serverRoot = getRequiredPropertyValue(pluginConfig, PLUGIN_CONFIG_PROP_SERVER_ROOT);
        return new File(serverRoot);
    }

    /**
     * Return the absolute path of this Apache server's executable (e.g. "C:\Program Files\Apache
     * Group\Apache2\bin\Apache.exe").
     *
     * @return the absolute path of this Apache server's executable (e.g. "C:\Program Files\Apache
     *         Group\Apache2\bin\Apache.exe")
     */
    @NotNull
    public File getExecutablePath() {
        Configuration pluginConfig = this.resourceContext.getPluginConfiguration();
        String executablePath = pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_EXECUTABLE_PATH, null);
        File executableFile;
        if (executablePath != null) {
            executableFile = resolvePathRelativeToServerRoot(executablePath);
        } else {
            String serverRoot = null;

            ApacheDirectiveTree tree = parseRuntimeConfiguration(true);
            List<ApacheDirective> directives = tree.search("/ServerRoot");
            if (!directives.isEmpty())
                if (!directives.get(0).getValues().isEmpty())
                    serverRoot = directives.get(0).getValues().get(0);

            SystemInfo systemInfo = this.resourceContext.getSystemInformation();
            if (systemInfo.getOperatingSystemType() != OperatingSystemType.WINDOWS) // UNIX
            {
                // Try some combinations in turn
                executableFile = new File(serverRoot, "bin/httpd");
                if (!executableFile.exists()) {
                    executableFile = new File(serverRoot, "bin/apache2");
                }
                if (!executableFile.exists()) {
                    executableFile = new File(serverRoot, "bin/apache");
                }
            } else // Windows
            {
                executableFile = new File(serverRoot, "bin/Apache.exe");
            }
        }

        return executableFile;
    }

    /**
     * @return The url the server is pinged for availability or null if the url is not set.
     */
    public @Nullable
    String getServerUrl() {
        return resourceContext.getPluginConfiguration().getSimpleValue(PLUGIN_CONFIG_PROP_URL, null);
    }

    /**
     * Returns the httpd.conf file
     * @return A File object that represents the httpd.conf file or null in case of error
     */
    public File getHttpdConfFile() {
        Configuration pluginConfig = this.resourceContext.getPluginConfiguration();
        PropertySimple prop = pluginConfig.getSimple(PLUGIN_CONFIG_PROP_HTTPD_CONF);
        if (prop == null || prop.getStringValue() == null)
            return null;
        return resolvePathRelativeToServerRoot(pluginConfig, prop.getStringValue());
    }

    /**
     * Return the absolute path of this Apache server's control script (e.g. "C:\Program Files\Apache
     * Group\Apache2\bin\Apache.exe").
     *
     * On Unix we need to try various locations, as some unixes have bin/ conf/ .. all within one root
     * and on others those are separated.
     *
     * @return the absolute path of this Apache server's control script (e.g. "C:\Program Files\Apache
     *         Group\Apache2\bin\Apache.exe")
     */
    @NotNull
    public File getControlScriptPath() {
        Configuration pluginConfig = this.resourceContext.getPluginConfiguration();
        String controlScriptPath = pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_CONTROL_SCRIPT_PATH, null);
        File controlScriptFile = null;
        if (controlScriptPath != null) {
            controlScriptFile = resolvePathRelativeToServerRoot(controlScriptPath);
        } else {
            boolean found = false;
            // First try server root as base
            String serverRoot = null;
            try {
                ApacheDirectiveTree tree = parseRuntimeConfiguration(true);
                List<ApacheDirective> directives = tree.search("/ServerRoot");
                if (!directives.isEmpty())
                    if (!directives.get(0).getValues().isEmpty())
                        serverRoot = directives.get(0).getValues().get(0);

            } catch (Exception e) {
                log.error("Could not load configuration parser.", e);
            }
            if (serverRoot != null) {
                for (String path : CONTROL_SCRIPT_PATHS) {
                    controlScriptFile = new File(serverRoot, path);
                    if (controlScriptFile.exists()) {
                        found = true;
                        break;
                    }
                }
            }

            //only try harder on the control script path on OSes with UNIX file system layout
            if (!found
                && resourceContext.getSystemInformation().getOperatingSystemType() != OperatingSystemType.WINDOWS) {
                String executablePath = pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_EXECUTABLE_PATH, null);
                if (executablePath != null) {
                    // this is now something like /usr/sbin/httpd .. trim off the last 2 parts
                    int i = executablePath.lastIndexOf(File.separatorChar);

                    if (i >= 0) {
                        executablePath = executablePath.substring(0, i);
                        i = executablePath.lastIndexOf(File.separatorChar);
                    }

                    if (i >= 0) {
                        executablePath = executablePath.substring(0, i);
                        for (String path : CONTROL_SCRIPT_PATHS) {
                            controlScriptFile = new File(executablePath, path);
                            if (controlScriptFile.exists()) {
                                found = true;
                                break;
                            }
                        }
                    }
                }
            }

            if (!found) {
                controlScriptFile = getExecutablePath(); // fall back to the httpd binary
            }
        }

        return controlScriptFile;
    }

    @NotNull
    public ConfigurationTimestamp getConfigurationTimestamp() {
        AugeasConfigurationApache config =
            new AugeasConfigurationApache(resourceContext.getTemporaryDirectory().getAbsolutePath(),
                resourceContext.getPluginConfiguration());
        return new ConfigurationTimestamp(config.getAllConfigurationFiles());
    }

    /**
     * This method is supposed to be called from {@link #updateResourceConfiguration(ConfigurationUpdateReport)}
     * of this resource and any child resources.
     * 
     * Based on the plugin configuration of this resource, the Apache instance is either restarted or left as is.
     * 
     * @param report the report is updated with the error message and status is set to failure if the restart fails.
     */
    public void finishConfigurationUpdate(ConfigurationUpdateReport report) {
        try {
            conditionalRestart();
        } catch (Exception e) {
            report.setStatus(ConfigurationUpdateStatus.FAILURE);
            report.setErrorMessageFromThrowable(e);
        }
    }

    /**
     * This method is akin to {@link #finishConfigurationUpdate(ConfigurationUpdateReport)} but should
     * be used in the {@link #createResource(CreateResourceReport)} method.
     * 
     * @param report the report is updated with the error message and status is set to failure if the restart fails.
     */
    public void finishChildResourceCreate(CreateResourceReport report) {
        try {
            conditionalRestart();
        } catch (Exception e) {
            report.setStatus(CreateResourceStatus.FAILURE);
            report.setException(e);
        }
    }

    /**
     * Conditionally restarts the server based on the settings in the plugin configuration of the server.
     * 
     * @throws Exception if the restart fails.
     */
    public void conditionalRestart() throws Exception {
        Configuration pluginConfig = resourceContext.getPluginConfiguration();
        boolean restart = pluginConfig.getSimple(PLUGIN_CONFIG_PROP_RESTART_AFTER_CONFIG_UPDATE).getBooleanValue();
        if (restart) {
            operationsDelegate.invokeOperation("graceful_restart", new Configuration());
        }
    }

    /**
     * This method checks whether the supplied node that has been deleted from the tree didn't leave
     * the file it was contained in empty.
     * If the file is empty after deleting the node, the file is automatically deleted.
     * @param tree TODO
     * @param deletedNode the node that has been deleted from the tree.
     */
    public void deleteEmptyFile(AugeasTree tree, AugeasNode deletedNode) {
        File file = tree.getFile(deletedNode);
        List<AugeasNode> fileContents = tree.match(file.getAbsolutePath() + AugeasTree.PATH_SEPARATOR + "*");

        if (fileContents.size() == 0) {
            file.delete();
        }
    }

    public Map<String, String> getModuleNames() {
        return moduleNames;
    }

    public ProcessInfo getCurrentProcessInfo() {
        return resourceContext.getNativeProcess();
    }

    public ApacheBinaryInfo getCurrentBinaryInfo() {
        return binaryInfo;
    }

    @NotNull
    private File resolvePathRelativeToServerRoot(@NotNull String path) {
        return resolvePathRelativeToServerRoot(this.resourceContext.getPluginConfiguration(), path);
    }

    //TODO this needs to go...
    @NotNull
    static File resolvePathRelativeToServerRoot(Configuration pluginConfig, @NotNull String path) {
        File file = new File(path);
        if (!file.isAbsolute()) {
            String serverRoot = getRequiredPropertyValue(pluginConfig, PLUGIN_CONFIG_PROP_SERVER_ROOT);
            file = new File(serverRoot, path);
        }

        return file;
    }

    @NotNull
    static String getRequiredPropertyValue(@NotNull Configuration config, @NotNull String propName) {
        String propValue = config.getSimpleValue(propName, null);
        if (propValue == null) {
            // Something's not right - neither autodiscovery, nor the config edit GUI, should ever allow this.
            throw new IllegalStateException("Required property '" + propName + "' is not set.");
        }

        return propValue;
    }

    public HttpdAddressUtility getAddressUtility() {
        String version = getVersion();
        return HttpdAddressUtility.get(version);
    }

    private String getNewVhostFileName(HttpdAddressUtility.Address address, String mask) {
        String filename = address.host + "_" + address.port;
        String fullPath = mask.replace("*", filename);

        File file = getFileRelativeToServerRoot(fullPath);

        int i = 1;
        while (file.exists()) {
            filename = address.host + "_" + address.port + "-" + (i++);
            fullPath = mask.replace("*", filename);
            file = getFileRelativeToServerRoot(fullPath);
        }
        return file.getAbsolutePath();
    }

    private void startEventPollers() {
        Configuration pluginConfig = this.resourceContext.getPluginConfiguration();
        Boolean enabled =
            Boolean.valueOf(pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_ERROR_LOG_EVENTS_ENABLED, null));
        if (enabled) {
            File errorLogFile =
                resolvePathRelativeToServerRoot(pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_ERROR_LOG_FILE_PATH,
                    DEFAULT_ERROR_LOG_PATH));
            ApacheErrorLogEntryProcessor processor =
                new ApacheErrorLogEntryProcessor(ERROR_LOG_ENTRY_EVENT_TYPE, errorLogFile);
            String includesPatternString =
                pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_ERROR_LOG_INCLUDES_PATTERN, null);
            if (includesPatternString != null) {
                try {
                    Pattern includesPattern = Pattern.compile(includesPatternString);
                    processor.setIncludesPattern(includesPattern);
                } catch (PatternSyntaxException e) {
                    throw new InvalidPluginConfigurationException("Includes pattern [" + includesPatternString
                        + "] is not a valid regular expression.");
                }
            }
            String minimumSeverityString =
                pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_ERROR_LOG_MINIMUM_SEVERITY, null);
            if (minimumSeverityString != null) {
                EventSeverity minimumSeverity = EventSeverity.valueOf(minimumSeverityString.toUpperCase());
                processor.setMinimumSeverity(minimumSeverity);
            }
            EventPoller poller =
                new LogFileEventPoller(this.eventContext, ERROR_LOG_ENTRY_EVENT_TYPE, errorLogFile, processor);
            this.eventContext.registerEventPoller(poller, 60, errorLogFile.getPath());
        }
    }

    private void stopEventPollers() {
        Configuration pluginConfig = this.resourceContext.getPluginConfiguration();
        File errorLogFile =
            resolvePathRelativeToServerRoot(pluginConfig.getSimpleValue(PLUGIN_CONFIG_PROP_ERROR_LOG_FILE_PATH,
                DEFAULT_ERROR_LOG_PATH));
        this.eventContext.unregisterEventPoller(ERROR_LOG_ENTRY_EVENT_TYPE, errorLogFile.getPath());
    }
    
    private File getFileRelativeToServerRoot(String path) {
        File f = new File(path);
        if (f.isAbsolute()) {
            return f;
        } else {
            return new File(getServerRoot(), path);
        }
    }

    public ApacheDirectiveTree parseFullConfiguration() {
        String httpdConfPath = getHttpdConfFile().getAbsolutePath();
        return ApacheServerDiscoveryComponent.parseFullConfiguration(httpdConfPath, binaryInfo.getRoot());
    }

    public ApacheDirectiveTree parseRuntimeConfiguration(boolean suppressUnknownModuleWarnings) {
        String httpdConfPath = getHttpdConfFile().getAbsolutePath();
        ProcessInfo processInfo = resourceContext.getNativeProcess();

        return ApacheServerDiscoveryComponent.parseRuntimeConfiguration(httpdConfPath, processInfo, binaryInfo,
            getModuleNames(), suppressUnknownModuleWarnings);
    }

    public boolean isAugeasEnabled() {

        Configuration pluginConfig = this.resourceContext.getPluginConfiguration();
        PropertySimple prop = pluginConfig.getSimple(AUGEAS_ENABLED);
        if (prop == null || prop.getStringValue() == null) {
            return false;
        }

        String val = prop.getStringValue();

        if (val.equals("yes")) {
            Augeas ag = null;
            try {
                ag = new Augeas();
            } catch (Exception e) {
                log.error("Augeas is enabled in configuration but was not found on the system.", e);
                throw new RuntimeException(CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);
            } finally {
                if (ag != null) {
                    try {
                        ag.close();
                    } catch (Exception e) {
                    }
                    ag = null;
                }
            }
            String version = getVersion();

            if (!version.startsWith("2.")) {
                log.error(CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);
                throw new RuntimeException(CONFIGURATION_NOT_SUPPORTED_ERROR_MESSAGE);
            }
            return true;
        } else {
            return false;
        }
    }

    private String getVersion() {
        String ret = resourceContext.getVersion();
        if (ret == null) {
            //strange, but this happens sometimes when 
            //the resource is synced with the server for the first
            //time after data purge on the agent side

            //let's determine the version from the binary info
            ret = binaryInfo.getVersion();
        }

        return ret;
    }
    
    ResourceContext getResourceContext() {
        return this.resourceContext;
    }

}
