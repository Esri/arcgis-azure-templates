#!/bin/bash

# Copyright 2025 Esri

# Licensed under the Apache License, Version 2.0 (the "License");

# you may not use this file except in compliance with the License.

# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software

# distributed under the License is distributed on an "AS IS" BASIS,

# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

# See the License for the specific language governing permissions and

# limitations under the License.​

set -euo pipefail
IFS=$'\n\t'

# -e: immediately exit if any command has a non-zero exit status 
# -o: prevents errors in a pipeline from being masked
# IFS new value is less likely to cause confusing bugs when looping arrays or arguments (e.g. $@)

usage() { echo "Usage: $0 -f <templateFileName> -p <templateParametersFileName> -g <resourceGroupName> -l <resourceGroupLocation> -s <storageAccountName> -r <storageAccountResourceGroupName>" 1>&2; exit 1; }

declare subscriptionId=""
declare resourceGroupName=""
declare deploymentName=""
declare resourceGroupLocation=""

# Initialize parameters specified from command line
while getopts ":f:p:g:s:l:r:" arg; do
    case "${arg}" in
        f)
            templateFileName=${OPTARG}
            ;;
        p)
            templateParametersFileName=${OPTARG}
            ;;
        g)
            resourceGroupName=${OPTARG}
            ;;
	    l)
            resourceGroupLocation=${OPTARG}
            ;;
        s)
            storageAccountName=${OPTARG}
            ;;
        r)
            storageAccountResourceGroupName=${OPTARG}
            ;;
        esac
done
shift $((OPTIND-1))

declare expiretime=$(date -u -d '4 hours' +%Y-%m-%dT%H:%MZ)
declare deploymentName="azuredeploy-$(date -u -d '30 minutes' +%m%d-%H%M)"
# Convert resourceGroupName to lowercase and remove non-alphanumeric characters
resourceGroupNameLower=$(echo "$resourceGroupName" | tr '[:upper:]' '[:lower:]')
declare storageContainerName="${resourceGroupNameLower//[^[:alnum:]]/}-stageartifacts"
declare templateFileNameTemp='azuredeploytemp.json'

declare existingSubnetName=""
declare existingVirtualNetworkName=""
declare outboundConnectivityMethod=""
declare natGatewayName=""
declare existingVnResourceGroup=""
declare natGatewayResourceGroup=""

# Function to determine Python command with fallback
get_python_command() {
    if command -v python &> /dev/null; then
        echo "python"
    elif command -v python3 &> /dev/null; then
        echo "python3"
    else
        echo "No Python interpreter found"
        exit 1
    fi
}
# Function to get a value from JSON using Python with fallback
get_value_from_json() {
    local key=$1
    local default=$2
    local python_cmd
    python_cmd=$(get_python_command)

    $python_cmd -c "import sys, json; params = json.load(open('$templateParametersFileName')); print(params['parameters']['$key']['value'])" 2>/dev/null || echo "$default"
}

# Load template parameters from JSON file
load_template_parameters() {
    if [ -f "$templateParametersFileName" ]; then
        echo "Loading template parameters from $templateParametersFileName..."
        existingSubnetName=$(get_value_from_json "subnetName" "")
        existingVirtualNetworkName=$(get_value_from_json "existingVirtualNetworkName" "")
        outboundConnectivityMethod=$(get_value_from_json "outboundConnectivityMethod" "")
        existingVnResourceGroup=$(get_value_from_json "virtualNetworkResourceGroupName" "")
        
        if [ "$outboundConnectivityMethod" == "NatGateway" ]; then
            natGatewayName=$(get_value_from_json "natGatewayName" "")
            natGatewayResourceGroup=$(get_value_from_json "natGatewayResourceGroup" "")

            # Check for errors in parameter extraction
            if [ -z "$natGatewayName" ] || [ -z "$natGatewayResourceGroup" ]; then
                echo "Error: Some Natgateway parameters are missing or invalid in $templateParametersFileName" >&2
                exit 1
            fi
        fi
    else
        echo "Warning: Template parameters file $templateParametersFileName not found"
    fi
}

# Function to attach NAT Gateway to Subnet
attach_nat_gateway() {
    if [ "$outboundConnectivityMethod" == "NatGateway" ]; then
        if [ -z "$natGatewayName" ]; then
            echo "Error: NAT Gateway name is not specified in the parameters."
            exit 1
        fi

        echo "Retrieving NAT Gateway ID for $natGatewayName..."
        natGatewayId=$(az network nat gateway show --resource-group "$natGatewayResourceGroup" --name "$natGatewayName" --query "id" --output tsv | tr -d '\r')
        if [ -z "$natGatewayId" ]; then
            echo "Error: NAT Gateway $natGatewayName not found in resource group $natGatewayResourceGroup"
            exit 1
        else
            echo "NAT Gateway ID: $natGatewayId"
            echo "Checking if subnet $existingSubnetName already has a NAT Gateway attached..."
            currentNatGatewayId=$(az network vnet subnet show --resource-group "$existingVnResourceGroup" --vnet-name "$existingVirtualNetworkName" --name "$existingSubnetName" --query "natGateway.id" --output tsv | tr -d '\r')
            if [ -n "$currentNatGatewayId" ]; then
                echo "NAT Gateway is already attached to subnet $existingSubnetName. Skipping NAT Gateway attachment."
            else
                echo "Updating subnet $existingSubnetName with NAT Gateway $natGatewayName..."
                update_output=$(az network vnet subnet update --resource-group "$existingVnResourceGroup" --vnet-name "$existingVirtualNetworkName" --name "$existingSubnetName" --nat-gateway "$natGatewayId" 2>&1)
                if [ $? != 0 ]; then
                    if [[ "$update_output" == *"SubnetWithNatGatewayAndBasicSkuResourceNotAllowed"* ]]; then
                        echo "Error: Cannot attach NAT Gateway $natGatewayName to subnet $existingSubnetName with Basic SKU Public IP or Load Balancer."
                    else
                        echo "Error: Failed to attach NAT Gateway $natGatewayName to subnet $existingSubnetName in virtual network $existingVirtualNetworkName"
                        echo "Details: $update_output"
                    fi
                    exit 1
                else
                    echo "NAT Gateway $natGatewayName has been attached to subnet $existingSubnetName in virtual network $existingVirtualNetworkName"
                fi
            fi
        fi
    else
        echo "No need to attach NAT Gateway to subnet"
    fi
}

echo "Retrieve deployment storage account details"
connection=$(az storage account show-connection-string --resource-group $storageAccountResourceGroupName --name $storageAccountName --query connectionString) 

endpoint='blob.core.windows.net'
IFS=';' read -r -a array <<< "$connection"
for element in "${array[@]}"
do
if [[ $element == EndpointSuffix* ]] ;
then
  endpoint=${element:15} # Extract Blob Endpoint
fi
done
IFS=$' \t\n'  # Unset IFS
artifactsLocation="https://$storageAccountName.blob.$endpoint/$storageContainerName"
echo "Using Artifacts Location $artifactsLocation"

# Create the storage container for the deployment artifacts
echo "Creating storage account $storageContainerName (if not exists)"
az storage container create --name $storageContainerName --connection-string $connection 1> /dev/null

echo "Generating SAS Token with expiry $expiretime for artifacts container $storageContainerName"
token=$(az storage container generate-sas --name $storageContainerName --expiry $expiretime --permissions r --output tsv --connection-string $connection)

# Generate the deployment artifacts parameters
deploymentParamsTempFile="$deploymentName.parameters.json"
python_cmd=$(get_python_command)
$python_cmd -c "import sys, json, base64; params = json.load(open('$templateParametersFileName')); params['parameters']['sslCertificateData']=(({'value':base64.b64encode(bytearray(open(params['parameters']['sslCertificateFileName']['value'],'rb').read())).decode()}) if 'sslCertificateFileName' in params['parameters'].keys() else {'value':base64.b64encode(urllib.request.urlopen(params['parameters']['sslCertificateFileUrl']['value']).read()).decode()}) if 'sslCertificatePassword' in params['parameters'].keys() else {'value':''}; params['parameters']['_artifactsLocationSasToken']={'value': '?$token'}; params['parameters']['_artifactsLocation']={'value': '$artifactsLocation'}; json.dump(params, open('$deploymentParamsTempFile','w'))"
templateFileObject=$(cat "$templateFileName")

###{"error":{"code":"InvalidRequestContent","message":"The request content was invalid and could not be deserialized: 'Error converting value 0 to type 'Azure.Deployments.Templates.Definitions.DeploymentParameterDefinition'. Path 'properties.parameters.sslCertificateData', line 1, position 2506.'."}}#

deploymentPrefix=$($python_cmd -c "import sys, json; params = json.load(open('$templateParametersFileName')); print(params['parameters']['deploymentPrefix']['value'])")
isBaseDeployment=$($python_cmd -c "import sys, json; params = json.load(open('$templateParametersFileName')); print(False) if 'federateSite' in params['parameters'].keys() else print(True)")
appGatewayName=$(get_value_from_json "appGatewayName" "default")
appGatewayResourceGroupName=$(get_value_from_json "appGatewayResourceGroupName" "default")

appg=$(az resource list --resource-group $appGatewayResourceGroupName --name $appGatewayName --resource-type "Microsoft.Network/applicationGateways" --query [].id -o tsv)
appgcheck=$(python -c "import sys, json; print(False) if '$appg' == None or '$appg' == '' else print(True)")
if [ $appgcheck = "True" ]
then
    echo "Exporting App gateway"
    appGatewayPropertiesFileName='appGatewayProperties.json'
    echo $(az resource show -g $appGatewayResourceGroupName -n $appGatewayName --resource-type "Microsoft.Network/applicationGateways" --include-response-body --query properties) > $appGatewayPropertiesFileName
    appGatewayPropertiesObject=$($python_cmd getAppGatewayObject.py --tmpf $templateParametersFileName --agpf $appGatewayPropertiesFileName)
    appGatewayTagsFileName='appGatewayTags.json'
    echo $(az resource show -g $appGatewayResourceGroupName -n $appGatewayName --resource-type "Microsoft.Network/applicationGateways" --include-response-body --query tags) > $appGatewayTagsFileName
    appGatewayTagsObject=$($python_cmd getAppGatewayTagsObject.py --dt existing --tmpf $templateParametersFileName --agtf $appGatewayTagsFileName)
    echo "${templateFileObject/APPGATEWAYPROPERTIESOBJECT/$appGatewayPropertiesObject}" > $templateFileNameTemp
    templateFileObject=$(cat "$templateFileNameTemp")
    echo "${templateFileObject/APPGATEWAYTAGS/$appGatewayTagsObject}" > $templateFileNameTemp
    rm $appGatewayPropertiesFileName
    rm $appGatewayTagsFileName
else
    echo "Using new App gateway block"
    # Load template parameters
    load_template_parameters
    # Attach the NAT Gateway to the subnet
    attach_nat_gateway

    appGatewayPropertiesFileName="AGGISproperties.json"
    if [ $isBaseDeployment = "True" ]
    then
        appGatewayPropertiesFileName="AGBaseproperties.json"
    else
        serverRole=$($python_cmd -c "import sys, json; params = json.load(open('$templateParametersFileName')); print(params['parameters']['serverRole']['value'])")
        if [ $serverRole = "GeoEventServer" ]
        then
            appGatewayPropertiesFileName="AGGeoeventGISproperties.json"
        fi
    fi
    
    appGatewayPropertiesObject=$($python_cmd getAppGatewayObject.py --dt new --tmpf $templateParametersFileName --agpf $appGatewayPropertiesFileName)
    echo "${templateFileObject/APPGATEWAYPROPERTIESOBJECT/$appGatewayPropertiesObject}" > $templateFileNameTemp
    appGatewayTagsObject=$($python_cmd getAppGatewayTagsObject.py --dt new --tmpf $templateParametersFileName)
    templateFileObject=$(cat "$templateFileNameTemp")
    echo "${templateFileObject/APPGATEWAYTAGS/$appGatewayTagsObject}" > $templateFileNameTemp
fi

# Create the resource group for the deployment
echo "Create resource group $resourceGroupName in $resourceGroupLocation (if not exists)"
az group create --location $resourceGroupLocation --name $resourceGroupName 1> /dev/null

# Upload artifacts to blob storage
for filename in *.ecp *.zip *.pfx *.prvc *.json *.ps1 *.cer
do
[ -e "$filename" ] || continue
echo "Uploading $filename to $storageContainerName"
az storage blob upload --container-name $storageContainerName --file $filename --name $filename --connection-string $connection --overwrite
done

# Validate the deployment
echo "Validate the template with name $deploymentName to resource group $resourceGroupName"
az deployment group validate --name $deploymentName --mode Incremental --resource-group $resourceGroupName --template-file $templateFileNameTemp --parameters $deploymentParamsTempFile 

# Start the deployment
echo "Start the deployment with name $deploymentName to resource group $resourceGroupName"
az deployment group create --name $deploymentName --mode Incremental --resource-group $resourceGroupName --template-file $templateFileNameTemp --parameters $deploymentParamsTempFile

echo "Delete temp file $deploymentParamsTempFile"
rm $deploymentParamsTempFile
echo "Delete temp file $templateFileNameTemp"
rm $templateFileNameTemp