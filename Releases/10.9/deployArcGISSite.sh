#!/bin/bash

# Copyright 2021 Esri

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
declare storageContainerName="${resourceGroupName//[^[:alnum:]]/}-stageartifacts"
declare templateFileNameTemp='azuredeploytemp.json'

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
$(python -c "import sys, json, base64; params = json.load(open('$templateParametersFileName')); params['parameters']['sslCertificateData']=(({'value':base64.b64encode(bytearray(open(params['parameters']['sslCertificateFileName']['value'],'rb').read())).decode()}) if 'sslCertificateFileName' in params['parameters'].keys() else {'value':base64.b64encode(urllib.request.urlopen(params['parameters']['sslCertificateFileUrl']['value']).read()).decode()}) if 'sslCertificatePassword' in params['parameters'].keys() else 0; params['parameters']['_artifactsLocationSasToken']={'value': '?$token'}; params['parameters']['_artifactsLocation']={'value': '$artifactsLocation'}; json.dump(params, open('$deploymentParamsTempFile','w'))")
templateFileObject=$(cat "$templateFileName")

deploymentPrefix=$(python -c "import sys, json; params = json.load(open('$templateParametersFileName')); print(params['parameters']['deploymentPrefix']['value'])")
isBaseDeployment=$(python -c "import sys, json; params = json.load(open('$templateParametersFileName')); print(False) if 'federateSite' in params['parameters'].keys() else print(True)")
appGatewayName=$(python -c "import sys, json; params = json.load(open('$templateParametersFileName')); print(params['parameters']['appGatewayName']['value'])")
appGatewayResourceGroupName=$(python -c "import sys, json; params = json.load(open('$templateParametersFileName')); print(params['parameters']['appGatewayResourceGroupName']['value'])")

appg=$(az resource list --resource-group $appGatewayResourceGroupName --name $appGatewayName --resource-type "Microsoft.Network/applicationGateways" --query [].id -o tsv)
appgcheck=$(python -c "import sys, json; print(False) if '$appg' == None or '$appg' == '' else print(True)")
if [ $appgcheck = "True" ]
then
    echo "Exporting App gateway"
    appGatewayPropertiesFileName='appGatewayProperties.json'
    echo $(az resource show -g $appGatewayResourceGroupName -n $appGatewayName --resource-type "Microsoft.Network/applicationGateways" --include-response-body --query properties) > $appGatewayPropertiesFileName
    appGatewayPropertiesObject=$(python getAppGatewayObject.py --tmpf $templateParametersFileName --agpf $appGatewayPropertiesFileName)
    appGatewayTagsFileName='appGatewayTags.json'
    echo $(az resource show -g $appGatewayResourceGroupName -n $appGatewayName --resource-type "Microsoft.Network/applicationGateways" --include-response-body --query tags) > $appGatewayTagsFileName
    echo "${templateFileObject/APPGATEWAYPROPERTIESOBJECT/$appGatewayPropertiesObject}" > $templateFileNameTemp
    appGatewayTagsObject=$(python getAppGatewayTagsObject.py --dt existing --tmpf $templateParametersFileName --agtf $appGatewayTagsFileName)
    templateFileObject=$(cat "$templateFileNameTemp")
    echo "${templateFileObject/APPGATEWAYTAGS/$appGatewayTagsObject}" > $templateFileNameTemp
    rm $appGatewayPropertiesFileName
    rm $appGatewayTagsFileName
else
    echo "Using new App gateway block"
    appGatewayPropertiesObject=$(cat 'AGGISproperties.json')
    if [ $isBaseDeployment = "True" ]
    then
        appGatewayPropertiesObject=$(cat 'AGBaseproperties.json')
    else
        serverRole=$(python -c "import sys, json; params = json.load(open('$templateParametersFileName')); print(params['parameters']['serverRole']['value'])")
        if [ $serverRole = "GeoEventServer" ]
        then
            appGatewayPropertiesObject=$(cat 'AGGeoeventGISproperties.json')
        fi
    fi
    echo "${templateFileObject/APPGATEWAYPROPERTIESOBJECT/$appGatewayPropertiesObject}" > $templateFileNameTemp
    appGatewayTagsObject=$(python getAppGatewayTagsObject.py --dt new --tmpf $templateParametersFileName)
    templateFileObject=$(cat "$templateFileNameTemp")
    echo "${templateFileObject/APPGATEWAYTAGS/$appGatewayTagsObject}" > $templateFileNameTemp
fi

# Create the resource group for the deployment
echo "Create resource group $resourceGroupName in $resourceGroupLocation (if not exists)"
az group create --location $resourceGroupLocation --name $resourceGroupName 1> /dev/null

# Upload artifacts to blob storage
for filename in *.ecp *.zip *.pfx *.prvc *.json *.ps1
do
[ -e "$filename" ] || continue
echo "Uploading $filename to $storageContainerName"
az storage blob upload --container-name $storageContainerName --file $filename --name $filename --connection-string $connection
done

# Start the deployment
echo "Start the deployment with name $deploymentName to resource group $resourceGroupName"
az deployment group create --name $deploymentName --mode Incremental --resource-group $resourceGroupName --template-file $templateFileNameTemp --parameters $deploymentParamsTempFile

echo "Delete temp file $deploymentParamsTempFile"
rm $deploymentParamsTempFile
echo "Delete temp file $templateFileNameTemp"
rm $templateFileNameTemp