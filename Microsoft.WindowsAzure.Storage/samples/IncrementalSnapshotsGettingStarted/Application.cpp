// -----------------------------------------------------------------------------------------
// <copyright file="Application.cpp" company="Microsoft">
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

#include "stdafx.h"
#include "samples_common.h"

#include <cpprest/containerstream.h>
#include <cpprest/filestream.h>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <cpprest/producerconsumerstream.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <thread>

namespace azure { namespace common { namespace helpers {
	
	const int DEFAULT_MAX_ITERATIONS = 20;
	const int THREAD_SLEEP_IN_MILLISECONDS = 1000;

	pplx::task<web::http::http_response> http_call_async(
		const utility::string_t& uri,
		const utility::string_t& body,
		const web::http::method method,
		const utility::string_t& content_type,
		const web::http::http_headers& request_headers)
	{
		web::http::client::http_client client(uri);

		web::http::http_request request(method);
		request.set_body(body, content_type);
		request.headers() = request_headers;
		
		return client.request(request).then([](web::http::http_response response)
			{
				return response;
			});
	}

	web::json::value track_operation_status(
		const utility::string_t& operation_uri,
		const utility::string_t& access_token)
	{
		utility::string_t payload_body(_XPLATSTR(""));
		utility::string_t content_type(_XPLATSTR("application/json"));

		utility::string_t authorization_header(_XPLATSTR("Bearer "));
		authorization_header.append(access_token);
		web::http::http_headers request_headers;
		request_headers.add(_XPLATSTR("Authorization"), authorization_header);

		utility::string_t status(_XPLATSTR("Running"));
		web::json::value output = web::json::value();
		int max_iterations = DEFAULT_MAX_ITERATIONS;

		do
		{
			ucout << _XPLATSTR("Waiting for operation to complete: #") << (DEFAULT_MAX_ITERATIONS - max_iterations) << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(THREAD_SLEEP_IN_MILLISECONDS));

			http_call_async(operation_uri, payload_body, web::http::methods::GET, content_type, request_headers).then(
				[&status, &output](web::http::http_response response)
				{
					web::json::value json_object = response.extract_json().get();
					status = json_object.at(_XPLATSTR("status")).as_string();

					if (status == _XPLATSTR("Succeeded"))
					{
						output = json_object; // .at(_XPLATSTR("properties")).at(_XPLATSTR("output"));
					}
				}).wait();
		} while ((status == _XPLATSTR("Running") || status == _XPLATSTR("InProgress")) && --max_iterations > 0);
		
		return output;
	}
}}} // namespace azure::common::helpers

namespace azure { namespace authentication { namespace helpers {

	pplx::task<utility::string_t> get_access_token_from_service_principal_async(
		const utility::string_t& authority,
		const utility::string_t& resource,
		const utility::string_t& tenant_id,
		const utility::string_t& application_id,
		const utility::string_t& application_secret)
	{
		utility::string_t auth_uri(authority);
		auth_uri.append(tenant_id);
		auth_uri.append(_XPLATSTR("/oauth2/token"));

		utility::string_t url_encoded_resource(web::http::uri::encode_data_string(resource));
		utility::string_t payload_body(_XPLATSTR("grant_type=client_credentials"));
		payload_body.append(_XPLATSTR("&client_id="));
		payload_body.append(application_id);
		payload_body.append(_XPLATSTR("&client_secret="));
		payload_body.append(application_secret);
		payload_body.append(_XPLATSTR("&resource="));
		payload_body.append(url_encoded_resource);

		utility::string_t content_type(_XPLATSTR("application/x-www-form-urlencoded"));
		web::http::http_headers request_headers;

		return azure::common::helpers::http_call_async(auth_uri, payload_body, web::http::methods::POST, content_type, request_headers).then([](web::http::http_response response)
			{
				return response.extract_json().get().at(_XPLATSTR("access_token")).as_string();
			});
	}

	pplx::task<utility::string_t> get_access_token_from_managed_identities_async(
		const utility::string_t& managed_identity_endpoint,
		const utility::string_t& resource)
	{
		utility::string_t url_encoded_resource(web::http::uri::encode_data_string(resource));

		utility::string_t auth_uri(managed_identity_endpoint);
		auth_uri.append(url_encoded_resource);

		utility::string_t payload_body(_XPLATSTR(""));
		utility::string_t content_type(_XPLATSTR("text/plain"));
		web::http::http_headers request_headers;
		request_headers.add(_XPLATSTR("Metadata"), _XPLATSTR("true"));

		return azure::common::helpers::http_call_async(auth_uri, payload_body, web::http::methods::GET, content_type, request_headers).then([](web::http::http_response response)
			{
				return response.extract_json().get().at(_XPLATSTR("access_token")).as_string();
			});
	}
}}} // namespace azure::authentication::helpers

namespace azure { namespace compute { namespace snapshots {

	pplx::task<void> create_incremental_snapshot_async(
		const utility::string_t& subscription_id,
		const utility::string_t& resource_group_name,
		const utility::string_t& snapshot_name,
		const utility::string_t& region,
		const utility::string_t& parent_disk_resource_uri,
		const utility::string_t& access_token)
	{
		utility::string_t create_snapshot_uri(_XPLATSTR("https://management.azure.com/subscriptions/"));
		create_snapshot_uri.append(subscription_id);
		create_snapshot_uri.append(_XPLATSTR("/resourceGroups/"));
		create_snapshot_uri.append(resource_group_name);
		create_snapshot_uri.append(_XPLATSTR("/providers/Microsoft.Compute/snapshots/"));
		create_snapshot_uri.append(snapshot_name);
		create_snapshot_uri.append(_XPLATSTR("?api-version=2019-03-01"));

		web::json::value json_payload;
		json_payload[_XPLATSTR("type")] = web::json::value::string(_XPLATSTR("Microsoft.Compute/snapshots"));
		json_payload[_XPLATSTR("name")] = web::json::value::string(snapshot_name);
		json_payload[_XPLATSTR("location")] = web::json::value::string(region);
		web::json::value json_payload_sku;
		json_payload_sku[_XPLATSTR("name")] = web::json::value::string(_XPLATSTR("Standard_LRS"));
		web::json::value json_payload_properties_creation_data;
		json_payload_properties_creation_data[_XPLATSTR("createOption")] = web::json::value::string(_XPLATSTR("Copy"));
		json_payload_properties_creation_data[_XPLATSTR("sourceResourceId")] = web::json::value::string(parent_disk_resource_uri);
		web::json::value json_payload_properties;
		json_payload_properties[_XPLATSTR("creationData")] = json_payload_properties_creation_data;
		json_payload_properties[_XPLATSTR("incremental")] = web::json::value::boolean(_XPLATSTR("true"));
		json_payload[_XPLATSTR("sku")] = json_payload_sku;
		json_payload[_XPLATSTR("properties")] = json_payload_properties;
		utility::stringstream_t stream;
		json_payload.serialize(stream);
		utility::string_t payload_body(stream.str());

		utility::string_t content_type(_XPLATSTR("application/json"));

		utility::string_t authorization_header(_XPLATSTR("Bearer "));
		authorization_header.append(access_token);
		web::http::http_headers request_headers;
		request_headers.add(_XPLATSTR("Authorization"), authorization_header);
		request_headers.add(_XPLATSTR("Content-Type"), _XPLATSTR("application/json"));

		return azure::common::helpers::http_call_async(create_snapshot_uri, payload_body, web::http::methods::PUT, content_type, request_headers).then(
			[access_token](web::http::http_response response)
			{
				utility::string_t async_operation_uri(response.headers()[_XPLATSTR("Azure-AsyncOperation")]);
				if (async_operation_uri.empty())
				{
					return;
				}

				web::json::value output = azure::common::helpers::track_operation_status(async_operation_uri, access_token);
				//ucout << _XPLATSTR("Track Operation_Status JSON Output: ") << output.serialize() << std::endl;
			});
	}

	pplx::task<utility::string_t> generate_sas_url_async(
		const utility::string_t& subscription_id,
		const utility::string_t& resource_group_name,
		const utility::string_t& snapshot_name,
		const utility::string_t& access_token)
	{
		utility::string_t get_snapshot_access_uri(_XPLATSTR("https://management.azure.com/subscriptions/"));
		get_snapshot_access_uri.append(subscription_id);
		get_snapshot_access_uri.append(_XPLATSTR("/resourceGroups/"));
		get_snapshot_access_uri.append(resource_group_name);
		get_snapshot_access_uri.append(_XPLATSTR("/providers/Microsoft.Compute/snapshots/"));
		get_snapshot_access_uri.append(snapshot_name);
		get_snapshot_access_uri.append(_XPLATSTR("/beginGetAccess?api-version=2019-03-01"));

		web::json::value get_snapshot_access_payload;
		get_snapshot_access_payload[_XPLATSTR("access")] = web::json::value::string(_XPLATSTR("Read")); // TODO: Make "access" a parameter to this function.
		get_snapshot_access_payload[_XPLATSTR("durationInSeconds")] = web::json::value::string(_XPLATSTR("3600")); // TODO: Make "durationInSeconds" a parameter to this function.
		utility::stringstream_t stream;
		get_snapshot_access_payload.serialize(stream);
		utility::string_t payload_body(stream.str());

		utility::string_t content_type(_XPLATSTR("application/json"));

		utility::string_t authorization_header(_XPLATSTR("Bearer "));
		authorization_header.append(access_token);
		web::http::http_headers request_headers;
		request_headers.add(_XPLATSTR("Authorization"), authorization_header);
		request_headers.add(_XPLATSTR("Content-Type"), _XPLATSTR("application/json"));

		return azure::common::helpers::http_call_async(get_snapshot_access_uri, payload_body, web::http::methods::POST, content_type, request_headers).then(
			[access_token](web::http::http_response response)
			{
				utility::string_t async_operation_uri(response.headers()[_XPLATSTR("Azure-AsyncOperation")]);
				if (async_operation_uri.empty())
				{
					return utility::string_t(_XPLATSTR(""));
				}

				web::json::value output = azure::common::helpers::track_operation_status(async_operation_uri, access_token);
				//ucout << _XPLATSTR("Track Operation_Status JSON Output: ") << output.serialize() << std::endl;
				utility::string_t sas_url(output.at(_XPLATSTR("properties")).at(_XPLATSTR("output")).at(_XPLATSTR("accessSAS")).as_string());
				return sas_url;
			});
	}
}}} // namespace azure::compute::snapshots

namespace azure { namespace storage { namespace samples {

	void incremental_snapshots_getting_started_sample()
    {
        try
        {
			// 1. Get the access token.
			utility::string_t access_token = azure::authentication::helpers::get_access_token_from_service_principal_async(aad_authority, aad_resource, aad_tenant_id, aad_application_id, aad_application_secret).get();
			//ucout << _XPLATSTR("Access Token: ") << access_token << std::endl;

			// 2. Create an incremental snapshot.
			azure::compute::snapshots::create_incremental_snapshot_async(subscription_id, resource_group_name, snapshot_name, region, managed_disk_resource_uri, access_token).get();

			// 3. Generate a SAS URL.
			utility::string_t sas_url = azure::compute::snapshots::generate_sas_url_async(subscription_id, resource_group_name, snapshot_name, access_token).get();
			ucout << _XPLATSTR("Snapshot SAS URL: ") << sas_url << std::endl;
        }
        catch (const std::exception& e)
        {
            ucout << _XPLATSTR("Error: ") << e.what() << std::endl;
        }
    }
}}} // namespace azure::storage::samples

int main(int argc, const char *argv[])
{
    azure::storage::samples::incremental_snapshots_getting_started_sample();
    return 0;
}

