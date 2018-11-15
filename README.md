"# Esri-ARM-Templates" 
1. Open a Cloud Shell
2. Clone this repo using git clone locally and upload the necessary artifacts (DSC.zip, Template File, Template Parameter File, deployArcGISSite.sh) to cloud shell fileshare.
3. Upload License and Cretificate File to cloud shell fileshare.
4. Edit the the ARM Templates parameters file you want to deploy.
5. Navigate to clouddrive folder in cloud shell fileshare on cloudshell.
5. Use the following to deploy the ArcGIS Site  
```./deployArcGISSite.sh -f <templateFileName> -p <templateParametersFileName> -g <resourceGroupName> -l <resourceGroupLocation> -s <storageAccountName> -r <storageAccountResourceGroupName>``` 
