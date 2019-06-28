// -----------------------------------------------------------------------------------------
// <copyright file="samples_common.h" company="Microsoft">
//    Copyright 2013 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
// </copyright>
// -----------------------------------------------------------------------------------------

#pragma once

#include "was/common.h"

namespace azure { namespace storage { namespace samples {

    // TODO: Put your account name and account key here
     utility::string_t storage_connection_string(_XPLATSTR("DefaultEndpointsProtocol=https;AccountName=myaccountname;AccountKey=myaccountkey"));

	// ***********************************************************************
	// ** Settings below are used in the Incremental Snapshots samples.     **
	// ***********************************************************************

	// ** AAD authentication settings: **
	// TODO: Put your Service Principal (SP) details below. You'll need the Tenant ID (AAD Directory ID), Application/Client ID, and Application Secret/Password.
	// Tip: You can generate an SP with the Azure CLI using a syntax like this and get the required info from the resulting JSON payload:
	//      az ad sp create-for-rbac -n "http://aad-app-for-incremental-snapshots" --role contributor --scopes "/subscriptions/{my-subsccription-id}/resourceGroups/My-RG"
	
	utility::string_t aad_tenant_id(_XPLATSTR("AAD-Tenant-ID"));
	utility::string_t aad_application_id(_XPLATSTR("AAD-Application-ID"));
	utility::string_t aad_application_secret(_XPLATSTR("AAD-Application-Secret"));

	// ** Incremental snapshot settings: **
	// TODO: Put your subscription, resource group, region, snapshot name, and parent disk resource URI below.

	utility::string_t subscription_id(_XPLATSTR("AZURE-SUBSCRIPTION-ID"));
	utility::string_t resource_group_name(_XPLATSTR("RESOURCE-GROUP-NAME"));
	utility::string_t region(_XPLATSTR("AZURE-REGION"));
	utility::string_t snapshot_name(_XPLATSTR("SNAPSHOT-NAME"));
	utility::string_t managed_disk_resource_uri(_XPLATSTR("subscriptions/[AZURE-SUBSCRIPTION-ID]/resourceGroups/[RESOURCE-GROUP-NAME]/providers/Microsoft.Compute/disks/[DISK-NAME]"));

	// ***********************************************************************
	// ** Settings below don't change that often and can be left untouched. **
	// ***********************************************************************

	// AAD resource and authority for authenticating against Service Principal or MSI.
	utility::string_t aad_resource(_XPLATSTR("https://management.azure.com/")); // Public cloud
	//utility::string_t aad_resource(_XPLATSTR("https://management.usgovcloudapi.net/")); // Gov cloud (Fairfax)
	//utility::string_t aad_resource(_XPLATSTR("https://management.microsoftazure.de/")); // Germany (Black Forest)
	//utility::string_t aad_resource(_XPLATSTR("https://management.chinacloudapi.cn/")); // China (Mooncake)

	utility::string_t aad_authority(_XPLATSTR("https://login.microsoftonline.com/")); // Public cloud
	//utility::string_t aad_authority(_XPLATSTR("https://login.microsoftonline.com/")); // Gov cloud (Fairfax)
	//utility::string_t aad_authority(_XPLATSTR("https://login.microsoftonline.de/")); // Germany (Black Forest)
	//utility::string_t aad_authority(_XPLATSTR("https://login.chinacloudapi.cn/")); // China (Mooncake)

	// MSI (typically http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource= or the older http://localhost:50342/oauth2/token?resource=)
	// Note: The resource query string parameter must be URI-encoded.
	utility::string_t msi_endpoint(_XPLATSTR("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource="));
}}} // namespace azure::storage::samples
