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

#include <was/storage_account.h>
#include <was/blob.h>

#include <cpprest/containerstream.h>
#include <cpprest/filestream.h>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <cpprest/producerconsumerstream.h>
#include <iostream>
#include <sstream>

namespace azure { namespace authentication { namespace utility {
	
	typedef std::wstring string_t;

	pplx::task<utility::string_t> http_post_async(
		const utility::string_t& uri,
		const utility::string_t& body,
		const web::http::method method,
		const utility::string_t& content_type,
		const bool is_msi = false)
	{
		web::http::client::http_client client(uri);

		web::http::http_request request(web::http::methods::POST);
		request.set_body(body, content_type);
		if (is_msi)
		{
			request.headers().add(_XPLATSTR("Metadata"), _XPLATSTR("true"));
		}

		return client.request(request).then([](web::http::http_response response)
			{
				//ucout << _XPLATSTR("Response Status Code: ") << response.status_code() << std::endl;
				//ucout << _XPLATSTR("Content type: ") << response.headers().content_type() << std::endl;
				//ucout << _XPLATSTR("Content length: ") << response.headers().content_length() << std::endl;

				if (response.headers().content_length() == 0 || response.status_code() != 200)
				{
					return utility::string_t(_XPLATSTR(""));
				}

				web::json::value json_object = response.extract_json().get();
				utility::string_t access_token = json_object.at(_XPLATSTR("access_token")).as_string();

				return access_token;
			});
	}

	pplx::task<utility::string_t> get_access_token_from_service_principal(
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

		return http_post_async(auth_uri, payload_body, web::http::methods::POST, content_type);
	}

	pplx::task<utility::string_t> get_access_token_from_managed_identities(
		const utility::string_t& managed_identity_endpoint,
		const utility::string_t& resource)
	{
		utility::string_t url_encoded_resource(web::http::uri::encode_data_string(resource));

		utility::string_t auth_uri(managed_identity_endpoint);
		auth_uri.append(url_encoded_resource);

		utility::string_t payload_body(_XPLATSTR(""));
		utility::string_t content_type(_XPLATSTR("text/plain"));

		return http_post_async(auth_uri, payload_body, web::http::methods::GET, content_type, true);
	}
}}} // namespace azure::authentication::utility

namespace azure { namespace storage { namespace samples {

	void incremental_snapshots_getting_started_sample()
    {
        try
        {
			utility::string_t access_token = azure::authentication::utility::get_access_token_from_service_principal(aad_authority, aad_resource, aad_tenant_id, aad_application_id, aad_application_secret).get();
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

