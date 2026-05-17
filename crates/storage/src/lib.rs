//! Storage backends for rmail.
//!
//! The mail engine uses this object-store implementation for S3-backed queue
//! storage and for rmailctl storage checks.

use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    config::{Builder as S3ConfigBuilder, Region},
    primitives::ByteStream,
    Client,
};
use aws_smithy_types::byte_stream::error::Error as ByteStreamError;
use bytes::Bytes;
use rmail_config::S3StorageConfig;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("S3 error: {0}")]
    S3(String),
    #[error("S3 body error: {0}")]
    Body(#[from] ByteStreamError),
}

#[derive(Clone)]
pub struct S3Store {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3Store {
    pub fn new(config: &S3StorageConfig) -> Self {
        let credentials = Credentials::new(
            config.access_key_id.clone(),
            config.secret_access_key.clone(),
            None,
            None,
            "rmail-config",
        );
        let mut builder = S3ConfigBuilder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .credentials_provider(credentials)
            .endpoint_url(config.endpoint.clone());
        if config.path_style {
            builder = builder.force_path_style(true);
        }
        let client = Client::from_conf(builder.build());
        Self {
            client,
            bucket: config.bucket.clone(),
            prefix: config.prefix.trim_matches('/').to_owned(),
        }
    }

    pub async fn put(&self, key: &str, bytes: impl Into<Bytes>) -> Result<(), StorageError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(key))
            .body(ByteStream::from(bytes.into()))
            .send()
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;
        Ok(())
    }

    pub async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(key))
            .send()
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;
        Ok(out.body.collect().await?.into_bytes())
    }

    pub async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.key(key))
            .send()
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;
        Ok(())
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let full_prefix = self.key(prefix);
        let out = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&full_prefix)
            .send()
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;
        let prefix_len = if self.prefix.is_empty() {
            0
        } else {
            self.prefix.len() + 1
        };
        Ok(out
            .contents()
            .iter()
            .filter_map(|obj| obj.key())
            .map(|key| key[prefix_len..].to_owned())
            .collect())
    }

    pub async fn healthcheck(&self) -> Result<(), StorageError> {
        let key = ".rmail-healthcheck";
        self.put(key, Bytes::from_static(b"ok")).await?;
        let body = self.get(key).await?;
        if body.as_ref() != b"ok" {
            return Err(StorageError::S3("healthcheck body mismatch".into()));
        }
        self.delete(key).await?;
        Ok(())
    }

    fn key(&self, key: &str) -> String {
        let key = key.trim_start_matches('/');
        if self.prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{}/{}", self.prefix, key)
        }
    }
}
