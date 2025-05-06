use mime_0_2::Mime as Mime2;
use mime_multipart::{generate_boundary, read_multipart_body, write_multipart, Node, Part};
use nsmf_openapi::*;
use hyper_0_10::header::{ContentType, Header, Headers};
use hyper::{
    body,
    header::{self, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Body, Client, Request,
};
use hyper::{HeaderMap, Response, StatusCode};
// use hyper_0_10::header::{ContentType, Headers};
// use mime_0_2::{Mime as Mime2, SubLevel, TopLevel};
use std::str;
use swagger_old::{ApiError, BodyExt, ByteArray};

pub async fn scp_dec_post_sm_contexts(
    status: u16,
    body: Vec<u8>,
    headers: HeaderMap,
) -> Result<PostSmContextsResponse, ApiError> {
    match status {
        201 => {
            let response_location =
                headers
                    .get(HeaderName::from_static("location"))
                    .ok_or(ApiError(String::from(
                        "Required response header Location for response 201 was not found.",
                    )))?;
            let response_location =
                TryInto::<nsmf_openapi::header::IntoHeaderValue<String>>::try_into(
                    response_location.clone(),
                ).map_err(|e| ApiError(format!("DATA Eroor")))?
                .0;
            if headers.get(CONTENT_TYPE).unwrap().to_str().unwrap() == "application/json" {
                // let body = response.into_body();
                // let body = body
                // 		.to_raw().await
                // 		.map_err(|e| ApiError(format!("Failed to read response: {}", e)))?;
                let body = str::from_utf8(&body).unwrap();
                let body = serde_json::from_str::<models::SmContextCreatedData>(body).unwrap();

                Ok(PostSmContextsResponse::SuccessfulCreationOfAnSMContext {
                    body:
                        PostSmContextsResponseSuccessfulCreationOfAnSMContext::WithoutBinaryBodyPart(
                            body,
                        ),
                    location: response_location,
                })
            } else {
                // Get multipart chunks.

                // Extract the top-level content type header.
                let content_type_mime = headers
                    .get(CONTENT_TYPE)
                    .ok_or("Missing content-type header".to_string())
                    .and_then(|v| {
                        v.to_str().map_err(|e| {
                            format!(
                                "Couldn't read content-type header value for PostSmContexts: {}",
                                e
                            )
                        })
                    })
                    .and_then(|v| {
                        v.parse::<Mime2>().map_err(|_e| {
                            format!("Couldn't parse content-type header value for PostSmContexts")
                        })
                    });

                // let body = response.into_body().to_raw().await.map_err(|e| ApiError(format!("Failed to read response: {}", e)))?;
                // Insert top-level content type header into a Headers object.
                let mut multi_part_headers = Headers::new();
                match content_type_mime {
                    Ok(content_type_mime) => {
                        multi_part_headers.set(ContentType(content_type_mime));
                    }
                    Err(e) => {
                        return Err(ApiError(String::from("Unable to create Bad Request response due to unable to read content-type header for PostSmContexts")));
                    }
                };

                let mut created_data = None;
                let mut binary_data_n2_information_content_id = None;
                let mut binary_data_n2_information = None;

                // &*body expresses the body as a byteslice, &mut provides a
                // mutable reference to that byteslice.
                let nodes = match read_multipart_body(&mut &*body, &multi_part_headers, false) {
                    Ok(nodes) => nodes,
                    Err(e) => {
                        return Err(ApiError(String::from("Unable to create Bad Request response due to unable to read content-type header for PostSmContexts")));
                    }
                };
                for node in nodes {
                    if let Node::Part(part) = node {
                        if let Some(content_type) = part.content_type().map(|x| format!("{}", x)) {
                            if content_type == "application/json" && created_data.is_none() {
                                // Extract JSON part.
                                let deserializer =
                                    &mut serde_json::Deserializer::from_slice(part.body.as_slice());
                                let json_data: models::SmContextCreatedData =
                                    serde_ignored::deserialize(deserializer, |path| {}).map_err(|e| ApiError(format!("Some Eror")))?;
                                // Push JSON part to return object.
                                if let Some(ref info) = json_data.n2_sm_info {
                                    binary_data_n2_information_content_id
                                        .replace(info.content_id.clone());
                                }
                                created_data.replace(json_data);
                            }
                        }
                        if let Some(content_id) = part
                            .headers
                            .get_raw("Content-ID")
                            .map(|x| std::str::from_utf8(x[0].as_slice()).unwrap())
                        {
                            binary_data_n2_information_content_id.as_ref().map(|id| {
                                if id == content_id {
                                    binary_data_n2_information.replace(part.body.clone());
                                }
                            });
                        }
                    } else {
                    }
                }
                let created_data = created_data.ok_or("missing created_data").map_err(|e| ApiError(format!("Some Eror")))?;
                Ok(PostSmContextsResponse::SuccessfulCreationOfAnSMContext {
                    body:
                        PostSmContextsResponseSuccessfulCreationOfAnSMContext::WithBinaryBodyPart {
                            json_data: created_data,
                            binary_data_n2_sm_information: binary_data_n2_information
                                .map(|f| swagger::ByteArray(f)),
                        },
                    location: response_location,
                })
            }
        }
        // TODO: other cases
        307 => Ok(PostSmContextsResponse::GenericError),
        308 => Ok(PostSmContextsResponse::GenericError),
        400 => Ok(PostSmContextsResponse::GenericError),
        403 => Ok(PostSmContextsResponse::GenericError),
        404 => Ok(PostSmContextsResponse::GenericError),
        411 => Ok(PostSmContextsResponse::GenericError),
        413 => Ok(PostSmContextsResponse::GenericError),
        415 => Ok(PostSmContextsResponse::GenericError),
        429 => Ok(PostSmContextsResponse::GenericError),
        500 => Ok(PostSmContextsResponse::GenericError),
        503 => Ok(PostSmContextsResponse::GenericError),
        504 => Ok(PostSmContextsResponse::GenericError),
        0 => {
            // let body = response.into_body();
            Ok(PostSmContextsResponse::GenericError)
        }
        code => {
            let headers = headers.clone();
            let body = body[0..100].to_vec();
            Err(ApiError(format!(
                "Unexpected response code {}:\n{:?}\n\n{}",
                code,
                headers,
                match String::from_utf8(body) {
                    Ok(body) => body,
                    Err(e) => format!("<Body was not UTF8: {:?}>", e),
                }
            )))
        }
    }
}

pub async fn scp_dec_update_sm_context(
    status: u16,
    body: Vec<u8>,
    headers: HeaderMap,
) -> Result<UpdateSmContextResponse, ApiError> {
    match status {
        200 => {
            if headers.get(CONTENT_TYPE).unwrap().to_str().unwrap() == "application/json" {
                // let body = response.into_body();
                // let body = body
                // 		.to_raw().await
                // 		.map_err(|e| ApiError(format!("Failed to read response: {}", e)))?;
                let body = str::from_utf8(&body).unwrap();
                let body = serde_json::from_str::<models::SmContextUpdatedData>(body).unwrap();

                Ok(UpdateSmContextResponse::SuccessfulUpdateOfAnSMContextWithContentInTheResponse(
					UpdateSmContextResponseSuccessfulUpdateOfAnSMContextWithContentInTheResponse::WithoutBinaryBodyPart(body)
				))
            } else {
                // Get multipart chunks.

                // Extract the top-level content type header.
                let content_type_mime = headers
                    .get(CONTENT_TYPE)
                    .ok_or("Missing content-type header".to_string())
                    .and_then(|v| {
                        v.to_str().map_err(|e| {
                            format!(
                                "Couldn't read content-type header value for UpdateSmContext: {}",
                                e
                            )
                        })
                    })
                    .and_then(|v| {
                        v.parse::<Mime2>().map_err(|_e| {
                            format!("Couldn't parse content-type header value for UpdateSmContext")
                        })
                    });

                // let body = response.into_body().to_raw().await.map_err(|e| ApiError(format!("Failed to read response: {}", e)))?;
                // Insert top-level content type header into a Headers object.
                let mut multi_part_headers = Headers::new();
                match content_type_mime {
                    Ok(content_type_mime) => {
                        multi_part_headers.set(ContentType(content_type_mime));
                    }
                    Err(e) => {
                        return Err(ApiError(String::from("Unable to create Bad Request response due to unable to read content-type header for UpdateSmContext")));
                    }
                };

                let mut created_data = None;
                let mut binary_data_n1_message_content_id = None;
                let mut binary_data_n1_message = None;
                let mut binary_data_n2_information_content_id = None;
                let mut binary_data_n2_information = None;

                // &*body expresses the body as a byteslice, &mut provides a
                // mutable reference to that byteslice.
                let nodes = match read_multipart_body(&mut &*body, &multi_part_headers, false) {
                    Ok(nodes) => nodes,
                    Err(e) => {
                        return Err(ApiError(String::from("Unable to create Bad Request response due to unable to read content-type header for UpdateSmContext")));
                    }
                };
                for node in nodes {
                    if let Node::Part(part) = node {
                        if let Some(content_type) = part.content_type().map(|x| format!("{}", x)) {
                            if content_type == "application/json" && created_data.is_none() {
                                // Extract JSON part.
                                let deserializer =
                                    &mut serde_json::Deserializer::from_slice(part.body.as_slice());
                                let json_data: models::SmContextUpdatedData =
                                    match serde_ignored::deserialize(deserializer, |path| {}) {
                                        Ok(json_data) => json_data,
                                        Err(e) => {
                                            return Err(ApiError(String::from("Unable to create Bad Request response for invalid body parameter models::UpdateSmContext due to schema")));
                                        }
                                    };
                                // Push JSON part to return object.
                                if let Some(ref info) = json_data.n1_sm_msg {
                                    binary_data_n1_message_content_id
                                        .replace(info.content_id.clone());
                                }
                                if let Some(ref info) = json_data.n2_sm_info {
                                    binary_data_n2_information_content_id
                                        .replace(info.content_id.clone());
                                }
                                created_data.replace(json_data);
                            }
                        }
                        if let Some(content_id) = part
                            .headers
                            .get_raw("Content-ID")
                            .map(|x| std::str::from_utf8(x[0].as_slice()).unwrap())
                        {
                            binary_data_n1_message_content_id.as_ref().map(|id| {
                                if id == content_id {
                                    binary_data_n1_message.replace(part.body.clone());
                                }
                            });
                            binary_data_n2_information_content_id.as_ref().map(|id| {
                                if id == content_id {
                                    binary_data_n2_information.replace(part.body.clone());
                                }
                            });
                        }
                    } else {
                        unimplemented!("No support for handling unexpected parts");
                        // unused_elements.push();
                    }
                }
                let created_data = match created_data {
                    Some(created_data) => created_data,
                    None => {
                        return Err(ApiError(String::from("Unable to create Bad Request response for missing body parameter SmContextUpdateData")));
                    }
                };
                Ok(UpdateSmContextResponse::SuccessfulUpdateOfAnSMContextWithContentInTheResponse(
					UpdateSmContextResponseSuccessfulUpdateOfAnSMContextWithContentInTheResponse::WithBinaryBodyPart {
						json_data: created_data,
						binary_data_n1_sm_message: binary_data_n1_message.map(|f| swagger::ByteArray(f)),
						binary_data_n2_sm_information: binary_data_n2_information.map(|f| swagger::ByteArray(f)),
					}
				))
            }
        }
        204 => {
            Ok(UpdateSmContextResponse::SuccessfulUpdateOfAnSMContextWithoutContentInTheResponse)
        }
        // TODO: other cases
        0 => {
            // let body = response.into_body();
            Ok(UpdateSmContextResponse::GenericError)
        }
        code => {
            let headers = headers;
            let body = body.to_vec();
            Err(ApiError(format!(
                "Unexpected response code {}:\n{:?}\n\n{}",
                code,
                headers,
                match String::from_utf8(body) {
                    Ok(body) => body,
                    Err(e) => format!("<Body was not UTF8: {:?}>", e),
                }
            )))
        }
    }
}

pub async fn scp_dec_release_sm_context(
    status: u16,
    body: Vec<u8>,
    headers: HeaderMap,
) -> Result<ReleaseSmContextResponse, ApiError> {
    match status {
        200 => {
            // let body = response.into_body();
            // 	let body = body
            // 			.to_raw().await
            // 			.map_err(|e| ApiError(format!("Failed to read response: {}", e)))?;
            let body = str::from_utf8(&body).unwrap();
            let body = serde_json::from_str::<models::SmContextReleasedData>(body).map_err(|e| ApiError(format!("Some Eror")))?;
            Ok(
                ReleaseSmContextResponse::SuccessfulReleaseOfAPDUSessionWithContentInTheResponse(
                    body,
                ),
            )
        }
        204 => {
            Ok(ReleaseSmContextResponse::SuccessfulReleaseOfAnSMContextWithoutContentInTheResponse)
        }
        // TODO: other cases
        0 => {
            // let body = response.into_body();
            Ok(ReleaseSmContextResponse::GenericError)
        }
        code => {
            let headers = headers.clone();
            let body = body.to_vec();
            Err(ApiError(format!(
                "Unexpected response code {}:\n{:?}\n\n{}",
                code,
                headers,
                match String::from_utf8(body) {
                    Ok(body) => body,
                    Err(e) => format!("<Body was not UTF8: {:?}>", e),
                }
            )))
        }
    }
}
