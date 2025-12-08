import sys, json, argparse, subprocess

def _arg_parser():
    parser = argparse.ArgumentParser(description="Update properties for App Gateway")
    parser.add_argument("--dt", default=None, help="Enterprise Deployment Type")
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

def create_cer_from_pfx(certFileName, certPassword):
    cerFileName = certFileName+".crt"
    p = subprocess.Popen(["openssl", "pkcs12", "-in", certFileName, "-out", certFileName+".crt", "-nokeys", "-clcerts", "-passin", "pass:{}".format(certPassword)], stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell=False, encoding='utf8')

    stdout, stderr = p.communicate(input="sd")
    if stderr or p.returncode != 0:
        print("error:" + stderr)
    if stdout:
        print(stdout)
    return cerFileName

def get_fingerprint_from_crt(certFileName):
    p = subprocess.Popen(["openssl", "x509", "-in", certFileName, "-noout", "-fingerprint"],stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell=False, encoding='utf8')
    stdout, stderr = p.communicate(input="sd")
    if stderr or p.returncode != 0:
        print("error:" + stderr)
    return stdout.split('=')[1]


def get_cert_string(certFileName):
    with open(certFileName, 'r') as file:
        cert = file.read()
    #cert_bytes = cert.encode('ascii')
    #return base64.b64encode(cert_bytes)
    return cert

def _main(args):
    params = json.load(open(args.tmpf))
    isBaseDeployment = False if 'federateSite' in params['parameters'].keys() else True
    usesSelfSignedInternalSSLCertificate =  params['parameters']['useSelfSignedInternalSSLCertificate']['value']
    if args.dt == "new":
        with open(args.agpf, 'r') as f:
            agraw = f.read()

        agtemp = json.load(open(args.agpf))
        trustedRootCertificateArrayList = agtemp['trustedRootCertificates']
        serverRootCertName = ""
        portalRootCertName = ""
        if not usesSelfSignedInternalSSLCertificate:
            serverInternalCertificateFileName = params['parameters']['serverInternalCertificateFileName']['value']
            serverInternalCertificatePassword = params['parameters']['serverInternalCertificatePassword']['value']
            server_crt_file = create_cer_from_pfx(serverInternalCertificateFileName, serverInternalCertificatePassword)
            server_crt_fingerprint = get_fingerprint_from_crt(server_crt_file)
            serverRootCertName = "RootCert_1";
            serverTrustedRootCertificate = {
                    "name": serverRootCertName,
                    "properties" : {
                        "data": get_cert_string(server_crt_file)
                    }
                }
            trustedRootCertificateArrayList.append(serverTrustedRootCertificate)

            if isBaseDeployment:
                agraw = agraw.replace("serverBackendSSLCert", serverRootCertName)
                portalInternalCertificateFileName = params['parameters']['portalInternalCertificateFileName']['value']
                portalInternalCertificatePassword = params['parameters']['portalInternalCertificatePassword']['value']
                portal_crt_file = create_cer_from_pfx(portalInternalCertificateFileName, portalInternalCertificatePassword)
                portal_crt_fingerprint = get_fingerprint_from_crt(portal_crt_file)
                portalRootCertName = serverRootCertName
                if server_crt_fingerprint != portal_crt_fingerprint:
                    portalRootCertName = "RootCert_2";
                    portalTrustedRootCertificate = {
                        "name": portalRootCertName,
                        "properties" : {
                            "data": get_cert_string(portal_crt_file)
                        }
                    }
                    trustedRootCertificateArrayList.append(portalTrustedRootCertificate)
                agraw = agraw.replace("portalBackendSSLCert", portalRootCertName)
            else:
                agraw = agraw.replace("variables('serverBackendSSLCertName')", "'{}'".format(serverRootCertName))
        else:
            serverTrustedRootCertificate = {
                "name":  "serverBackendSSLCert" if isBaseDeployment else "[variables('serverBackendSSLCertName')]",
                "properties" : {
                    "data": "[split(reference(concat('generateSSLCertificatesCustomExtension-',deployment().name),'2018-05-01').outputs.instanceView.value.substatuses[0].message, '###DATA###')[0]]"
                }
            }
            trustedRootCertificateArrayList.append(serverTrustedRootCertificate)
            if isBaseDeployment:
                portalTrustedRootCertificate = {
                    "name": "portalBackendSSLCert",
                    "properties" : {
                        "data": "[split(reference(concat('generateSSLCertificatesCustomExtension-',deployment().name),'2018-05-01').outputs.instanceView.value.substatuses[0].message, '###DATA###')[1]]"
                    }
                }
                trustedRootCertificateArrayList.append(portalTrustedRootCertificate)
             
        ag = json.loads(agraw)
        ag['trustedRootCertificates'] = trustedRootCertificateArrayList
        print(json.dumps(ag, indent=4))
    else:
        ag = json.load(open(args.agpf))
        delete_keys_from_dict(ag,"resourceGroup")
        delete_keys_from_dict(ag,"provisioningState")
    
        del ag['operationalState']
        #sslCertificatesArrayList = ag['sslCertificates']
        #for cert in sslCertificatesArrayList:
        #    del cert['properties']['publicCertData'] ##publicCertData
        #    if cert['name'] == "frontendCert":
        #        cert['properties']['data'] ="[parameters('sslCertificateData')]"
        #        cert['properties']['password'] ="[parameters('sslCertificatePassword')]"

        trustedRootCertificateArrayList = ag['trustedRootCertificates']
        serverRootCertName = ""
        portalRootCertName = ""
        usesSelfSignedInternalSSLCertificate =  params['parameters']['useSelfSignedInternalSSLCertificate']['value']
        if not usesSelfSignedInternalSSLCertificate:
            serverInternalCertificateFileName = params['parameters']['serverInternalCertificateFileName']['value']
            serverInternalCertificatePassword = params['parameters']['serverInternalCertificatePassword']['value']
            server_crt_file = create_cer_from_pfx(serverInternalCertificateFileName, serverInternalCertificatePassword)
            server_crt_fingerprint = get_fingerprint_from_crt(server_crt_file)
            if isBaseDeployment:
                portalInternalCertificateFileName = params['parameters']['portalInternalCertificateFileName']['value']
                portalInternalCertificatePassword = params['parameters']['portalInternalCertificatePassword']['value']
                portal_crt_file = create_cer_from_pfx(portalInternalCertificateFileName, portalInternalCertificatePassword)
                portal_crt_fingerprint = get_fingerprint_from_crt(portal_crt_file)

            addServerRootCertToList = True
            addPortalRootCertToList = True
            certNamePrefix = "RootCert"
            currentMaxIndex = 0
            for cert in trustedRootCertificateArrayList:
                certIndex = cert['name'].split("_")[1]
                if certIndex > currentMaxIndex:
                    currentMaxIndex = certIndex
            
                text_file = open(cert['name']+".crt", "w")
                text_file.write("-----BEGIN CERTIFICATE-----\n"+cert['properties']['data']+"\n-----END CERTIFICATE-----")
                text_file.close()
                certFingerPrint = get_fingerprint_from_crt(cert['name']+".crt")
                if server_crt_fingerprint == certFingerPrint and not addServerRootCertToList:
                    serverRootCertName = cert['name']
                    addServerRootCertToList = False
            
                if isBaseDeployment and portal_crt_fingerprint == certFingerPrint and not addPortalRootCertToList:
                    portalRootCertName = cert['name']
                    addPortalRootCertToList = False
        
            if addServerRootCertToList:
                currentMaxIndex = currentMaxIndex + 1
                serverRootCertName = (certNamePrefix + "_" + currentMaxIndex)
                serverTrustedRootCertificate = {
                    "name": serverRootCertName,
                    "properties" : {
                        "data": get_cert_string(server_crt_file)
                    }
                }
                trustedRootCertificateArrayList.append(serverTrustedRootCertificate)
            if isBaseDeployment and addPortalRootCertToList:
                if portal_crt_fingerprint != server_crt_fingerprint:
                    currentMaxIndex = currentMaxIndex + 1
                    portalRootCertName = (certNamePrefix + "_" + currentMaxIndex)
                    portalTrustedRootCertificate = {
                        "name": portalRootCertName,
                        "properties" : {
                            "data": get_cert_string(portal_crt_file)
                        }
                    }
                    trustedRootCertificateArrayList.append(portalTrustedRootCertificate)
                else:
                    portalRootCertName = serverRootCertName

        if isBaseDeployment:
            deploymentPrefix = params['parameters']['deploymentPrefix']['value']
            if usesSelfSignedInternalSSLCertificate:
                for cert in trustedRootCertificateArrayList:
                    if cert['name'] == "serverBackendSSLCert": 
                        cert['properties']['data'] = "[split(reference(concat('generateSSLCertificatesCustomExtension-',deployment().name),'2018-05-01').outputs.instanceView.value.substatuses[0].message, '###DATA###')[0]]"
                    if cert['name'] == "portalBackendSSLCert": 
                        cert['properties']['data'] = "[split(reference(concat('generateSSLCertificatesCustomExtension-',deployment().name),'2018-05-01').outputs.instanceView.value.substatuses[0].message, '###DATA###')[1]]"
            else:
                backendHttpSettingsArrayList = ag['backendHttpSettingsCollection']
                for setting in backendHttpSettingsArrayList:
                    if setting['Name'] == (deploymentPrefix+"PortalHttpsSetting"):
                       setting['properties']['trustedRootCertificates'] = [
                            {
                                "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}')]".format(serverRootCertName)
                            }
                        ]
                    if setting['Name'] == (deploymentPrefix+"ServerHttpsSetting"):
                        setting['properties']['trustedRootCertificates'] = [
                            {
                                "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}')]".format(portalRootCertName)
                            }
                        ]
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
            securityTagOption = 'Federated' if params['parameters']['federateSite']['value'] is True else 'StandAlone'
            serverRole = params['parameters']['serverRole']['value']
            serverContext = params['parameters']['serverContext']['value']
            geoeventServerContext = params['parameters']['geoeventServerContext']['value'] if serverRole == "GeoEventServer" else None

            if usesSelfSignedInternalSSLCertificate:
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

            skipAdditionalHttpSettings = False
            backendHttpSettingsArrayList = ag['backendHttpSettingsCollection']
            if not any(x for x in backendHttpSettingsArrayList if x['name'] == (serverContext + "-" + securityTagOption + "ServerHttpsSetting")):
                serverBackendHttpSetting = {
                    "name":"[variables('serverBackendHttpsSettingName')]",
                    "properties":{
                        "port": (443 if serverRole == "NotebookServer" else (20443 if serverRole == "MissionServer" else 6443)),
                        "protocol":"Https",
                        "cookieBasedAffinity":"Disabled",
                        "connectionDraining":{
                            "enabled":True,
                            "drainTimeoutInSec":60
                        },
                        "pickHostNameFromBackendAddress":True,
                        "path":"/arcgis/",
                        "requestTimeout": (900 if serverRole == "NotebookServer" else 180),
                        "probe":{
                            "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/probes/', variables('serverBackendProbeName'))]"
                        },
                        "trustedRootCertificates":[
                            {
                                "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/', variables('serverBackendSSLCertName'))]" if usesSelfSignedInternalSSLCertificate else "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}'))]".format(serverRootCertName)
                            }
                        ]
                    }
                }

                backendHttpSettingsArrayList.append(serverBackendHttpSetting)
            else:
                skipAdditionalHttpSettings = True
                if serverRootCertName != "":
                    for httpSetting in backendHttpSettingsArrayList:
                        if httpSetting['name'] == (serverContext + "-" + securityTagOption + "ServerHttpsSetting"):
                            setting['properties']['trustedRootCertificates'] = [
                                {
                                    "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}')]".format(serverRootCertName)
                                }
                            ]
                        if serverRole == "GeoEventServer":
                            if httpSetting['name'] == (serverContext + "-" + securityTagOption + "GeoeventServerHttpsSetting"):
                                setting['properties']['trustedRootCertificates'] = [
                                    {
                                        "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}')]".format(serverRootCertName)
                                    }
                                ]
                            if httpSetting['name'] == (serverContext + "-" + securityTagOption + "WSGeoeventServerHttpsSetting"):
                                setting['properties']['trustedRootCertificates'] = [
                                    {
                                        "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}')]".format(serverRootCertName)
                                    }
                                ]
                        if serverRole == "MissionServer":
                            if httpSetting['name'] == (serverContext + "-" + securityTagOption + "WSMissionServerHttpsSetting"):
                                setting['properties']['trustedRootCertificates'] = [
                                    {
                                        "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}')]".format(serverRootCertName)
                                    }
                                ]
                        if serverRole == "WorkflowManagerServer":
                            if httpSetting['name'] == (serverContext + "-" + securityTagOption + "WFMServerWorkflowHttpsSetting"):
                                setting['properties']['trustedRootCertificates'] = [
                                    {
                                        "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}')]".format(serverRootCertName)
                                    }
                                ]
        
            if serverRole == "GeoEventServer" and not skipAdditionalHttpSettings:
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
                                    "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/', variables('serverBackendSSLCertName'))]" if usesSelfSignedInternalSSLCertificate else "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}'))]".format(serverRootCertName)
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
                                    "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/', variables('serverBackendSSLCertName'))]" if usesSelfSignedInternalSSLCertificate else "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}'))]".format(serverRootCertName)
                                }
                            ]
                        }
                    }
                    backendHttpSettingsArrayList.append(wsGeoeventServerBackendHttpSetting)
        
            if serverRole == "MissionServer" and not skipAdditionalHttpSettings:
                if not any(x for x in backendHttpSettingsArrayList if x['name'] == (serverContext + "-" + securityTagOption + "WSMissionServerHttpsSetting")):
                    wsMissionServerBackendHttpSetting = {
                        "name":"[variables('wsMissionServerBackendHttpsSettingName')]",
                        "properties":{
                            "port": 20301,
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
                                    "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/', variables('serverBackendSSLCertName'))]" if usesSelfSignedInternalSSLCertificate else "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}'))]".format(serverRootCertName)
                                }
                            ]
                        }
                    }
                    backendHttpSettingsArrayList.append(wsMissionServerBackendHttpSetting)
            
            if serverRole == "WorkflowManagerServer" and not skipAdditionalHttpSettings:
                if not any(x for x in backendHttpSettingsArrayList if x['name'] == (serverContext + "-" + securityTagOption + "WFMServerWorkflowHttpsSetting")):
                    wsMissionServerBackendHttpSetting = {
                        "name":"[variables('wfmServerWorkflowBackendHttpsSettingName')]",
                        "properties":{
                            "port": 13443,
                            "protocol":"Https",
                            "cookieBasedAffinity":"Disabled",
                            "connectionDraining":{
                                "enabled":True,
                                "drainTimeoutInSec":60
                            },
                            "pickHostNameFromBackendAddress":True,
                            "path":"/workflow/",
                            "requestTimeout":540,
                            "probe":{
                                "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/probes/', variables('serverBackendProbeName'))]"
                            },
                            "trustedRootCertificates":[
                                {
                                    "id": "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/', variables('serverBackendSSLCertName'))]" if usesSelfSignedInternalSSLCertificate else "[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/trustedRootCertificates/{}'))]".format(serverRootCertName)
                                }
                            ]
                        }
                    }
                    backendHttpSettingsArrayList.append(wsMissionServerBackendHttpSetting)

            ag['backendHttpSettingsCollection'] = backendHttpSettingsArrayList

            urlPathMapArrayList = ag['urlPathMaps'][0]['properties']['pathRules']
            if not any(x for x in urlPathMapArrayList if x['name'] == (serverContext + "-" + securityTagOption + "ServerPathRule")):
                pathRule = {
                    "name":"[variables('serverPathRuleName')]",
                    "properties":{
                        "paths":[
                            "[concat('/', parameters('serverContext'), '/*')]",
                            "[concat('/', parameters('serverContext'))]",
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

            if serverRole == "MissionServer":
                if not any(x for x in urlPathMapArrayList if x['name'] == (serverContext + "-" + securityTagOption + "WSMissionServerPathRule")):
                    wsMissionPathRule = {
                        "name":"[variables('wsMissionServerPathRuleName')]",
                        "properties":{
                            "paths":[
                                "[concat('/', parameters('serverContext'), 'wss/*')]"
                            ],
                            "backendAddressPool":{
                                "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/backendAddressPools/',variables('serverBackendPoolName'))]"
                            },
                            "backendHttpSettings":{
                                "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/backendHttpSettingsCollection/', variables('wsMissionServerBackendHttpsSettingName'))]"
                            },
                            "rewriteRuleSet":{
                                "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/rewriteRuleSets/',variables('wsMissionServerRewriteRuleSetName'))]"
                            }
                        }
                    }
                    urlPathMapArrayList.append(wsMissionPathRule)

            if serverRole == "WorkflowManagerServer":
                if not any(x for x in urlPathMapArrayList if x['name'] == (serverContext + "-" + securityTagOption + "WFMServerWorkflowPathRule")):
                    wfmPathRule = {
                        "name":"[variables('wfmServerWorkflowPathRuleName')]",
                        "properties":{
                            "paths":[
                                "[concat('/', parameters('serverContext'), '/workflow/*')]"
                            ],
                            "backendAddressPool":{
                                "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/backendAddressPools/',variables('serverBackendPoolName'))]"
                            },
                            "backendHttpSettings":{
                                "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/backendHttpSettingsCollection/', variables('wfmServerWorkflowBackendHttpsSettingName'))]"
                            },
                            "rewriteRuleSet":{
                                "id":"[concat(resourceId(parameters('appGatewayResourceGroupName'),'Microsoft.Network/applicationGateways', parameters('appGatewayName')), '/rewriteRuleSets/',variables('wfmServeRewriteRuleSetName'))]"
                            }
                        }
                    }
                    urlPathMapArrayList.append(wfmPathRule)

            ag['urlPathMaps'][0]['properties']['pathRules'] = urlPathMapArrayList
        
            probesArrayList = ag["probes"]
            if not any(x for x in probesArrayList if x['name'] == (serverContext + "-" + securityTagOption + "ServerProbeName")):
                probe = {
                    "name":"[variables('serverBackendProbeName')]",
                    "properties":{
                        "protocol":"Https",
                        "path": f"/{serverContext}/rest/info/healthcheck" if serverRole == "NotebookServer" else "/arcgis/rest/info/healthcheck",
                        "interval":30,
                        "timeout":30,
                        "unhealthyThreshold":3,
                        "pickHostNameFromBackendHttpSettings":True,
                        "minServers":0,
                        "match":{
                            "statusCodes":["200"]
                        }
                    }
                }
                if serverRole == "MissionServer":
                    probe.properties["port"] = 20443
                probesArrayList.append(probe)

            if serverRole == "GeoEventServer":
                if not any(x for x in probesArrayList if x['name'] == (geoeventServerContext + "-" + securityTagOption + "GeoeventServerProbeName")):
                    probe = {
                        "name":"[variables('geoeventServerProbeName')]",
                        "properties":{
                            "protocol":"Https",
                            "path":"/geoevent/manager",
                            "interval":30,
                            "timeout":30,
                            "unhealthyThreshold":3,
                            "pickHostNameFromBackendHttpSettings":True,
                            "minServers":0,
                            "match":{
                                "statusCodes":["200-399"]
                            }
                        }
                    }
                    probesArrayList.append(probe)

            if serverRole == "WorkflowManagerServer":
                if not any(x for x in probesArrayList if x['name'] == (serverContext + "-" + securityTagOption + "WFMServerProbeName")):
                    probe = {
                        "name":"[variables('wfmServerProbeName')]",
                        "properties":{
                            "protocol":"Https",
                            "path":"/workflow/healthCheck",
                            "interval":30,
                            "timeout":30,
                            "unhealthyThreshold":3,
                            "pickHostNameFromBackendHttpSettings":True,
                            "minServers":0,
                            "match":{
                                "statusCodes":["200"]
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
                                    "pattern" : r"[concat('(https?)://[^/]+\\/(?:arcgis|',parameters('serverContext'),')(.*)$')]" if serverRole == "NotebookServer" else ("[concat('(https?):\/\/[^\/]+:20443\/(?:arcgis|',parameters('serverContext'),')(.*)$')]" if serverRole == "MissionServer" else r"[concat('(https?):\/\/[^\/]+:6443\/(?:arcgis|',parameters('serverContext'),')(.*)$')]" ),
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
                                        "pattern" : r"[concat('(https?):\/\/[^\/]+:6143\/(?:geoevent|',parameters('geoeventServerContext'),')(.*)$')]",
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
                                        "pattern" : r"[concat('(wss?):\/\/[^\/]+:6143\/(?:arcgis|',parameters('geoeventServerContext'),')(.*)$')]",
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
            if serverRole == "MissionServer":
                if not any(x for x in rewriteRuleSetArrayList if x['name'] == (serverContext + "-" + securityTagOption + "WSMissionServerRewriteRuleSet")):
                    wsMissionRewriteRuleSet =  {
                        "name":"[variables('wsMissionServerRewriteRuleSetName')]",
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
                                    "name":"WSMissionServerRewriteRule",
                                    "conditions":[{
                                        "variable" : "http_resp_Location",
                                        "pattern" : r"[concat('(wss?):\/\/[^\/]+:20301\/(?:arcgis|',parameters('serverContext'),')(.*)$')]",
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
                                                "headerValue": "[concat('{http_resp_Location_1}://{http_req_host}/',parameters('serverContext'),'wss','{http_resp_Location_2}')]"
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                    rewriteRuleSetArrayList.append(wsMissionRewriteRuleSet)
            if serverRole == "WorkflowManagerServer":
                if not any(x for x in rewriteRuleSetArrayList if x['name'] == (serverContext + "-" + securityTagOption + "WFMServerRewriteRuleSet")):
                    wfmServerRewriteRuleSet =  {
                        "name":"[variables('wfmServeRewriteRuleSetName')]",
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
                                    "name":"WFMServerRewriteRule",
                                    "conditions":[{
                                        "variable" : "http_resp_Location",
                                        "pattern" : r"[concat('(https?)://[^/]+:13443\\/(?:arcgis|',parameters('serverContext'),'|workflow)(.*)$')]",
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
                                                "headerValue": "[concat('{http_resp_Location_1}://{http_req_host}/',parameters('serverContext'),'wss','{http_resp_Location_2}')]"
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                    rewriteRuleSetArrayList.append(wfmServerRewriteRuleSet)

            ag['rewriteRuleSets'] = rewriteRuleSetArrayList
        print(json.dumps(ag, indent=4))

if __name__ == "__main__":
    sys.exit(_main(_arg_parser()))