use aws_sdk_sqs::types::Message;
use serde::Deserialize;
use super::sqs::{
    S3Event, S3EventRecord, S3EventName, S3Message, S3Bucket, S3Object, S3EventVersion,
    ProcessingError
};

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct CrowdstrikeEvent {
    pub cid: String,
    pub timestamp: i64,
    #[serde(rename = "fileCount")]
    pub file_count: i64,
    #[serde(rename = "totalSize")]
    pub total_size: i64,
    pub bucket: String,
    #[serde(rename = "pathPrefix")]
    pub path_prefix: String,
    pub files: Vec<CrowdstrikeFile>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct CrowdstrikeFile {
    pub path: String,
    pub size: i64,
    pub checksum: String,
}

// Parse a Crowdstrike SQS message and format it to S3 event notification into an S3Event
pub fn parse_crowdstrike_sqs_message(
    message: Message,
    region: &str
) -> Result<S3Event, ProcessingError> {
    let sqs_body = message.body.unwrap_or_default();
    debug!(message = "Crowdstrike SQS message body", body = %sqs_body);

    match serde_json::from_str::<CrowdstrikeEvent>(&sqs_body) {
        Ok(cs_event) => {
            // Create a synthetic S3Event
            let mut s3_records = Vec::new();

            for file in &cs_event.files {
                let s3_record = S3EventRecord {
                    event_version: S3EventVersion { major: 2, minor: 0 },
                    event_source: "aws:s3".to_string(),
                    aws_region: region.to_string(),
                    event_name: S3EventName {
                        kind: "ObjectCreated".to_string(),
                        name: "Put".to_string(),
                    },
                    s3: S3Message {
                        bucket: S3Bucket {
                            name: cs_event.bucket.clone(),
                        },
                        object: S3Object {
                            key: file.path.clone(),
                        },
                    },
                };

                s3_records.push(s3_record);
            }

            Ok(S3Event { records: s3_records })
        },
        Err(err) => {
            Err(ProcessingError::InvalidSqsMessage {
                source: (err),
                message_id: message
                    .message_id
                    .clone()
                    .unwrap_or_else(|| "<empty>".to_owned()),
            })
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_sqs::types::Message;

    fn create_test_message(body: Option<String>, message_id: Option<String>) -> Message {
        Message::builder()
            .set_body(body)
            .set_message_id(message_id)
            .build()
    }

    #[test]
    fn test_parse_valid_crowdstrike_message() {
        let valid_json = r#"
        {
            "cid": "123e4567-e89b-12d3-a456-426614174000",
            "timestamp": 1620000000,
            "fileCount": 2,
            "totalSize": 1024,
            "bucket": "test-bucket",
            "pathPrefix": "prefix/",
            "files": [
                {
                    "path": "prefix/file1.txt",
                    "size": 512,
                    "checksum": "abc123"
                },
                {
                    "path": "prefix/file2.txt",
                    "size": 512,
                    "checksum": "def456"
                }
            ]
        }"#;

        let message = create_test_message(
            Some(valid_json.to_string()),
            Some("test-message-id".to_string())
        );

        let result = parse_crowdstrike_sqs_message(message, "us-east-1");

        assert!(result.is_ok());
        let s3_event = result.unwrap();
        assert_eq!(s3_event.records.len(), 2);

        let first_record = &s3_event.records[0];
        assert_eq!(first_record.event_version.major, 2);
        assert_eq!(first_record.event_version.minor, 0);
        assert_eq!(first_record.event_source, "aws:s3");
        assert_eq!(first_record.aws_region, "us-east-1");
        assert_eq!(first_record.event_name.kind, "ObjectCreated");
        assert_eq!(first_record.event_name.name, "Put");
        assert_eq!(first_record.s3.bucket.name, "test-bucket");
        assert_eq!(first_record.s3.object.key, "prefix/file1.txt");

        let second_record = &s3_event.records[1];
        assert_eq!(second_record.s3.object.key, "prefix/file2.txt");
    }

    #[test]
    fn test_parse_empty_files_list() {
        let json_with_empty_files = r#"
        {
            "cid": "123e4567-e89b-12d3-a456-426614174000",
            "timestamp": 1620000000,
            "fileCount": 0,
            "totalSize": 0,
            "bucket": "test-bucket",
            "pathPrefix": "prefix/",
            "files": []
        }"#;

        let message = create_test_message(
            Some(json_with_empty_files.to_string()),
            Some("test-message-id".to_string())
        );

        let result = parse_crowdstrike_sqs_message(message, "us-east-1");

        assert!(result.is_ok());
        let s3_event = result.unwrap();
        assert_eq!(s3_event.records.len(), 0);
    }

    #[test]
    fn test_parse_invalid_json() {
        let invalid_json = r#"{ "invalid": "json"#;

        let message = create_test_message(
            Some(invalid_json.to_string()),
            Some("invalid-json-message-id".to_string())
        );

        let result = parse_crowdstrike_sqs_message(message, "us-east-1");

        assert!(result.is_err());
        if let Err(ProcessingError::InvalidSqsMessage { message_id, .. }) = result {
            assert_eq!(message_id, "invalid-json-message-id");
        } else {
            panic!("Expected InvalidSqsMessage error");
        }
    }

    #[test]
    fn test_parse_missing_required_fields() {
        let missing_fields_json = r#"
        {
            "cid": "123e4567-e89b-12d3-a456-426614174000",
            "timestamp": 1620000000,
            "fileCount": 2,
            "totalSize": 1024,
            "bucket": "test-bucket",
            "pathPrefix": "prefix/"
        }"#;

        let message = create_test_message(
            Some(missing_fields_json.to_string()),
            Some("missing-fields-message-id".to_string())
        );

        let result = parse_crowdstrike_sqs_message(message, "us-east-1");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_message() {
        let empty_message = create_test_message(
            None,
            Some("empty-message-id".to_string())
        );

        let result = parse_crowdstrike_sqs_message(empty_message, "us-east-1");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_message_with_empty_body() {
        let empty_body_message = create_test_message(
            Some("".to_string()),
            Some("empty-body-message-id".to_string())
        );

        let result = parse_crowdstrike_sqs_message(empty_body_message, "us-east-1");

        assert!(result.is_err());
    }
}