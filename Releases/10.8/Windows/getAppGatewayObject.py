import sys, json, argparse

def _arg_parser():
    parser = argparse.ArgumentParser(description="Update properties for App Gateway")
    parser.add_argument("--agpf", default=None, help="App Gateway Properties Temp File Name")
    parser.add_argument("--tmpf", default=None, help="Template Parameters File Name")
    return parser.parse_args()

def delete_keys_from_dict(d, to_delete):
    if isinstance(to_delete, str):
        to_delete = [to_delete]
    if isinstance(d, dict):
        for single_to_delete in set(to_delete):
            if single_to_delete in d:
                del d[single_to_delete]
        for k, v in d.items():
            delete_keys_from_dict(v, to_delete)
    elif isinstance(d, list):
        for i in d:
            delete_keys_from_dict(i, to_delete)
    return d

def _main(args):
    ag = json.load(open(args.agpf))
    params = json.load(open(args.tmpf))
    isBaseDeployment = False if 'federateSite' in params['parameters'].keys() else True
    delete_keys_from_dict(ag,"resourceGroup")
    delete_keys_from_dict(ag,"provisioningState")
    
    del ag['operationalState']
    #sslCertificatesArrayList = ag['sslCertificates']
    #for cert in sslCertificatesArrayList:
    #    del cert['properties']['publicCertData'] ##publicCertData
    #    if cert['name'] == "frontendCert":
    #        cert['properties']['data'] ="[parameters('sslCertificateData')]"
    #        cert['properties']['password'] ="[parameters('sslCertificatePassword')]"
    if isBaseDeployment:
        deploymentPrefix = params['parameters']['deploymentPrefix']['value']
    
        trustedRootCertificateArrayList = ag['trustedRootCertificates']
        for cert in trustedRootCertificateArrayList:
            if cert['name'] == "serverBackendSSLCert": 
                cert['properties']['data'] = "[split(reference(concat('generateSSLCertificatesCustomExtension-',deployment().name),'2018-05-01').outputs.instanceView.value.substatuses[0].message, '###DATA###')[0]]"
            if cert['name'] == "portalBackendSSLCert": 
                cert['properties']['data'] = "[split(reference(concat('generateSSLCertificatesCustomExtension-',deployment().name),'2018-05-01').outputs.instanceView.value.substatuses[0].message, '###DATA###')[1]]"
        ag['trustedRootCertificates'] = trustedRootCertificateArrayList

        backendAddressPoolsArrayList = ag['backendAddressPools']
        for backendPool in backendAddressPoolsArrayList:
            if backendPool['name'] == (deploymentPrefix + "ServerBackendPool"):
                backendPool['properties'] = {
                        "copy": [
                            {
                                "name": "backendAddresses",
                                "count": "[variables('numberOfServerVirtualMachines')]",
                                "input": {
                                    "fqdn": "[concat( variables('serverVirtualMachineNames')[copyIndex('backendAddresses')], '.', if(equals(string(parameters('joinWindowsDomain')), 'True'),parameters('windowsDomainName'), reference(concat(variables('serverVirtualMachineNames')[copyIndex('backendAddresses')],'-',variables('nicName'))).dnsSettings.internalDomainNameSuffix))]"
                                }
                            }
                        ]
                    }
            if backendPool['name'] == (deploymentPrefix + "PortalBackendPool"):
                backendPool['properties'] = {
                        "copy": [
                            {
                                "name": "backendAddresses",
                                "count": "[variables('numberOfPortalVirtualMachines')]",
                                "input": {
                                    "fqdn": "[concat( variables('portalVirtualMachineNames')[copyIndex('backendAddresses')], '.', if(equals(string(parameters('joinWindowsDomain')), 'True'),parameters('windowsDomainName'), reference(concat(variables('portalVirtualMachineNames')[copyIndex('backendAddresses')],'-',variables('nicName'))).dnsSettings.internalDomainNameSuffix))]"
                                }
                            }
                        ]
                    }
        ag['backendAddressPools'] = backendAddressPoolsArrayList
    else:
        securityTagOption = 'Federated' if params['parameters']['federateSite'] is True else 'StandAlone'
        serverRole = params['parameters']['serverRole']['value']
        serverContext = params['parameters']['serverContext']['value']
        geoeventServerContext = params['parameters']['geoeventServerContext']['value'] if serverRole == "GeoEventServer" else None

        trustedRootCertificateArrayList = ag['trustedRootCertificates']
        certCheck = False
        for cert in trustedRootCertificateArrayList:
            if cert['name'] == (serverContext + "-" + securityTagOption + "ServerBackendSSLCert"): 
                cert['properties']['data'] = "[split(reference(concat('generateSSLCertificatesCustomExtension-',deployment().name),'2018-05-01').outputs.instanceView.value.substatuses[0].message, '###DATA###')[0]]"
                certCheck = True
                break
        if not certCheck:
            serverTrustedRootCertificate = {
                "name":"[variables('serverBackendSSLCertName')]",
                "properties":{ 
                    "data":"[split(reference(concat('generateSSLCertificatesCustomExtension-',deployment().name),'2018-05-01').outputs.instanceView.value.substatuses[0].message, '###DATA###')[0]]"
                }
            }
            trustedRootCertificateArrayList.append(serverTrustedRootCertificate)
        ag['trustedRootCertificates'] = trustedRootCertificateArrayList

        backendAddressPoolsArrayList = ag['backendAddressPools']
        backendPoolCheck = False
        for backendPool in backendAddressPoolsArrayList:
            if backendPool['name'] == (serverContext + "-" + securityTagOption + "ServerBackendPool"):
                backendPool['properties'] = {
                    "copy": [
                        {
                            "name":"backendAddresses",
                            "count":"[variables('numberOfVirtualMachines')]",
                            "input":{
                                "fqdn":"[concat( variables('virtualMachineNames')[copyIndex('backendAddresses')], '.', if(equals(string(parameters('joinWindowsDomain')), 'True'),parameters('windowsDomainName'), reference(concat(variables('virtualMachineNames')[copyIndex('backendAddresses')],'-',variables('nicName'))).dnsSettings.internalDomainNameSuffix))]"
                            } 
                        }
                    ]
                }
                backendPoolCheck = True
                break
        if not backendPoolCheck:
            serverBackendAddressPool ={
                    "name":"[variables('serverBackendPoolName')]",
                    "properties":{
                        "copy": [
                            {
                                "name":"backendAddresses",
                                "count":"[variables('numberOfVirtualMachines')]",
                                "input":{
                                    "fqdn":"[concat( variables('virtualMachineNames')[copyIndex('backendAddresses')], '.', if(equals(string(parameters('joinWindowsDomain')), 'True'),parameters('windowsDomainName'), reference(concat(variables('virtualMachineNames')[copyIndex('backendAddresses')],'-',variables('nicName'))).dnsSettings.internalDomainNameSuffix))]"
                                } 
                            }
                        ]
                    }
                }
            backendAddressPoolsArrayList.append(serverBackendAddressPool)
        ag['backendAddressPools'] = backendAddressPoolsArrayList

        backendHttpSettingsArrayList = ag['backendHttpSettingsCollection']
        if not any(x for x in backendHttpSettingsArrayList if x['name'] == (serverContext + "-" + securityTagOption + "ServerHttpsSetting")):
            serverBackendHttpSetting = {
                "name":"[variables('serverBackendHttpsSettingName')]",
                "properties":{
                    "port": (11443 if serverRole == "NotebookServer" else 6443),
                    "protocol":"Https",
                    "cookieBasedAffinity":"Disabled",
                    "connectionDraining":{
                        "enabled":True,
                        "drainTimeoutInSec":60
                    },
                    "pickHostNameFromBackendAddress":True,
                    "path":"/arcgis/",
                    "requestTimeout":180,
                    "probe":{
                        "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/probes/', variables('serverBackendProbeName'))]"
                    },
                    "trustedRootCertificates":[
                        {
                            "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/', variables('serverBackendSSLCertName'))]"
                        }
                    ]
                }
            }
            backendHttpSettingsArrayList.append(serverBackendHttpSetting)
        
        if serverRole == "GeoEventServer":
            if not any(x for x in backendHttpSettingsArrayList if x['name'] == (geoeventServerContext + "-" + securityTagOption + "GeoeventServerHttpsSetting")):
                geoeventServerBackendHttpSetting = {
                    "name":"[variables('geoeventServerBackendHttpsSettingName')]",
                    "properties":{
                        "port": 6143,
                        "protocol":"Https",
                        "cookieBasedAffinity":"Disabled",
                        "connectionDraining":{
                            "enabled":True,
                            "drainTimeoutInSec":60
                        },
                        "pickHostNameFromBackendAddress":True,
                        "path":"/geoevent/",
                        "requestTimeout":180,
                        "probe":{
                            "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/probes/', variables('geoeventServerProbeName'))]"
                        },
                        "trustedRootCertificates":[
                            {
                                "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/', variables('serverBackendSSLCertName'))]"
                            }
                        ]
                    }
                }
                backendHttpSettingsArrayList.append(geoeventServerBackendHttpSetting)
            if not any(x for x in backendHttpSettingsArrayList if x['name'] == (geoeventServerContext + "-" + securityTagOption + "WSGeoeventServerHttpsSetting")):
                wsGeoeventServerBackendHttpSetting = {
                    "name":"[variables('wsGeoeventServerBackendHttpsSettingName')]",
                    "properties":{
                        "port": 6143,
                        "protocol":"Https",
                        "cookieBasedAffinity":"Disabled",
                        "connectionDraining":{
                            "enabled":True,
                            "drainTimeoutInSec":60
                        },
                        "pickHostNameFromBackendAddress":True,
                        "path":"/arcgis/",
                        "requestTimeout":180,
                        "probe":{
                            "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/probes/', variables('geoeventServerProbeName'))]"
                        },
                        "trustedRootCertificates":[
                            {
                                "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/', variables('serverBackendSSLCertName'))]"
                            }
                        ]
                    }
                }
                backendHttpSettingsArrayList.append(wsGeoeventServerBackendHttpSetting)
        
        ag['backendHttpSettingsCollection'] = backendHttpSettingsArrayList

        urlPathMapArrayList = ag['urlPathMaps'][0]['properties']['pathRules']
        if not any(x for x in urlPathMapArrayList if x['name'] == (serverContext + "-" + securityTagOption + "ServerPathRule")):
            pathRule = {
                "name":"[variables('serverPathRuleName')]",
                "properties":{
                    "paths":[
                        "[concat('/', parameters('serverContext'), '/*')]"
                    ],
                    "backendAddressPool":{
                        "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/backendAddressPools/',variables('serverBackendPoolName'))]"
                    },
                    "backendHttpSettings":{
                        "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/backendHttpSettingsCollection/', variables('serverBackendHttpsSettingName'))]"
                    },
                    "rewriteRuleSet":{
                        "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/rewriteRuleSets/',variables('serverRewriteRuleSetName'))]"
                    }
                }
            }
            urlPathMapArrayList.append(pathRule)
        
        if serverRole == "GeoEventServer":
            if not any(x for x in urlPathMapArrayList if x['name'] == (geoeventServerContext + "-" + securityTagOption + "GeoeventServerPathRule")):
                geoeventPathRule = {
                    "name":"[variables('geoeventServerPathRuleName')]",
                    "properties":{
                        "paths":[
                            "[concat('/', parameters('geoeventServerContext'), '/*')]"
                        ],
                        "backendAddressPool":{
                            "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/backendAddressPools/',variables('serverBackendPoolName'))]"
                        },
                        "backendHttpSettings":{
                            "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/backendHttpSettingsCollection/', variables('geoeventServerBackendHttpsSettingName'))]"
                        },
                        "rewriteRuleSet":{
                            "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/rewriteRuleSets/',variables('geoeventServerRewriteRuleSetName'))]"
                        }
                    }
                }
                urlPathMapArrayList.append(geoeventPathRule)
            if not any(x for x in urlPathMapArrayList if x['name'] == (geoeventServerContext + "-" + securityTagOption + "WSGeoeventServerPathRule")):
                wsGeoeventPathRule = {
                    "name":"[variables('wsGeoeventServerPathRuleName')]",
                    "properties":{
                        "paths":[
                            "[concat('/', parameters('geoeventServerContext'), 'wss/*')]"
                        ],
                        "backendAddressPool":{
                            "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/backendAddressPools/',variables('serverBackendPoolName'))]"
                        },
                        "backendHttpSettings":{
                            "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/backendHttpSettingsCollection/', variables('wsGeoeventServerBackendHttpsSettingName'))]"
                        },
                        "rewriteRuleSet":{
                            "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/rewriteRuleSets/',variables('wsGeoeventServerRewriteRuleSetName'))]"
                        }
                    }
                }
                urlPathMapArrayList.append(wsGeoeventPathRule)
        ag['urlPathMaps'][0]['properties']['pathRules'] = urlPathMapArrayList
        
        probesArrayList = ag["probes"]
        if not any(x for x in probesArrayList if x['name'] == (serverContext + "-" + securityTagOption + "ServerProbeName")):
            probe = {
                "name":"[variables('serverBackendProbeName')]",
                "properties":{
                    "protocol":"Https",
                    "path":"/arcgis/rest/info/healthcheck",
                    "interval":30,
                    "timeout":30,
                    "unhealthyThreshold":3,
                    "pickHostNameFromBackendHttpSettings":True,
                    "minServers":0,
                    "match":{
                        "statusCodes":["200-404"]
                    }
                }
            }
            probesArrayList.append(probe)

        if serverRole == "GeoEventServer":
            if not any(x for x in probesArrayList if x['name'] == (geoeventServerContext + "-" + securityTagOption + "GeoeventServerProbeName")):
                probe = {
                    "name":"[variables('geoeventServerProbeName')]",
                    "properties":{
                        "protocol":"Https",
                        "path":"/geoevent/admin",
                        "interval":30,
                        "timeout":30,
                        "unhealthyThreshold":3,
                        "pickHostNameFromBackendHttpSettings":True,
                        "minServers":0,
                        "match":{
                            "statusCodes":["200-404"]
                        }
                    }
                }
                probesArrayList.append(probe)
        ag['probes'] = probesArrayList
        
        rewriteRuleSetArrayList = ag['rewriteRuleSets']
        if not any(x for x in rewriteRuleSetArrayList if x['name'] == (serverContext + "-" + securityTagOption + "ServerRewriteRuleSet")):
            rewriteRuleSet = {
                "name":"[variables('serverRewriteRuleSetName')]",
                "properties":{
                "rewriteRules":[
                        {
                            "ruleSequence":50,
                            "name":"XForwardedHostRewrite",
                            "conditions":[],
                            "actionSet":{
                                "requestHeaderConfigurations":[
                                    {
                                        "headerName":"X-Forwarded-Host",
                                        "headerValue":"{http_req_host}"
                                    }
                                ],
                                "responseHeaderConfigurations":[]
                            }
                        },
                        {
                            "ruleSequence":100,
                            "name":"ServerRewriteRule",
                            "conditions":[{
                                "variable" : "http_resp_Location",
                                "pattern" : r"(https?):\/\/[^\/]+:11443\/(?:arcgis)(.*)$" if serverRole == "NotebookServer" else r"(https?):\/\/[^\/]+:6443\/(?:arcgis)(.*)$",
                                "ignoreCase" : True,
                                "negate" : False
                            }],
                            "actionSet":{
                                "requestHeaderConfigurations":[],
                                "responseHeaderConfigurations":[
                                    {
                                        "headerName":"RewriteLocationValue",
                                        "headerValue":"[concat('{http_resp_Location_1}://{http_req_host}/',parameters('serverContext'),'{http_resp_Location_2}')]"
                                    },
                                    {
                                        "headerName":"Location",
                                        "headerValue":"[concat('{http_resp_Location_1}://{http_req_host}/',parameters('serverContext'),'{http_resp_Location_2}')]"
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
            rewriteRuleSetArrayList.append(rewriteRuleSet)
        if serverRole == "GeoEventServer":
            if not any(x for x in rewriteRuleSetArrayList if x['name'] == (geoeventServerContext + "-" + securityTagOption + "GeoeventServerRewriteRuleSet")):
                geoeventRewriteRuleSet = {
                    "name":"[variables('geoeventServerRewriteRuleSetName')]",
                    "properties":{
                    "rewriteRules":[
                            {
                                "ruleSequence":50,
                                "name":"XForwardedHostRewrite",
                                "conditions":[],
                                "actionSet":{
                                    "requestHeaderConfigurations":[
                                        {
                                            "headerName":"X-Forwarded-Host",
                                            "headerValue":"{http_req_host}"
                                        }
                                    ],
                                    "responseHeaderConfigurations":[]
                                }
                            },
                            {
                                "ruleSequence":100,
                                "name":"geoeventServerRewriteRule",
                                "conditions":[{
                                    "variable" : "http_resp_Location",
                                    "pattern" : r"(https?):\/\/[^\/]+:6143\/(?:geoevent)(.*)$",
                                    "ignoreCase" : True,
                                    "negate" : False
                                }],
                                "actionSet":{
                                    "requestHeaderConfigurations":[],
                                    "responseHeaderConfigurations":[
                                        {
                                            "headerName":"RewriteLocationValue",
                                            "headerValue":"[concat('{http_resp_Location_1}://{http_req_host}/',parameters('geoeventServerContext'),'{http_resp_Location_2}')]"
                                        },
                                        {
                                            "headerName":"Location",
                                            "headerValue":"[concat('{http_resp_Location_1}://{http_req_host}/',parameters('geoeventServerContext'),'{http_resp_Location_2}')]"
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
                rewriteRuleSetArrayList.append(geoeventRewriteRuleSet)
            if not any(x for x in rewriteRuleSetArrayList if x['name'] == (geoeventServerContext + "-" + securityTagOption + "WSGeoeventServerRewriteRuleSet")):
                wsGeoeventRewriteRuleSet =  {
                    "name":"[variables('wsGeoeventServerRewriteRuleSetName')]",
                    "properties":{
                    "rewriteRules":[
                            {
                                "ruleSequence":50,
                                "name":"XForwardedHostRewrite",
                                "conditions":[],
                                "actionSet":{
                                    "requestHeaderConfigurations":[
                                        {
                                            "headerName":"X-Forwarded-Host",
                                            "headerValue":"{http_req_host}"
                                        }
                                    ],
                                    "responseHeaderConfigurations":[]
                                }
                            },
                            {
                                "ruleSequence":100,
                                "name":"WSGeoeventServerRewriteRule",
                                "conditions":[{
                                    "variable" : "http_resp_Location",
                                    "pattern" : r"(https?):\/\/[^\/]+:6143\/(?:arcgis)(.*)$",
                                    "ignoreCase" : True,
                                    "negate" : False
                                }],
                                "actionSet":{
                                    "requestHeaderConfigurations":[],
                                    "responseHeaderConfigurations":[
                                        {
                                            "headerName":"RewriteLocationValue",
                                            "headerValue":"[concat('{http_resp_Location_1}://{http_req_host}/',parameters('geoeventServerContext'),'{http_resp_Location_2}')]"
                                        },
                                        {
                                            "headerName":"Location",
                                            "headerValue": "[concat('{http_resp_Location_1}://{http_req_host}/',parameters('geoeventServerContext'),'wss','{http_resp_Location_2}')]"
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
                rewriteRuleSetArrayList.append(wsGeoeventRewriteRuleSet)
        ag['rewriteRuleSets'] = rewriteRuleSetArrayList
    print(json.dumps(ag, indent=4))
if __name__ == "__main__":
    sys.exit(_main(_arg_parser()))