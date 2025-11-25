use crate::config::Config;
use crate::security::classification_client::ClassificationClient;
use anyhow::Result;

pub struct MlDetector {
    client: ClassificationClient,
}

impl MlDetector {
    pub fn new(client: ClassificationClient) -> Self {
        Self { client }
    }

    pub fn new_from_config() -> Result<Self> {
        let config = Config::global();

        let model_name = config
            .get_param::<String>("SECURITY_PROMPT_BERT_MODEL")
            .ok();
        let endpoint = config
            .get_param::<String>("SECURITY_PROMPT_BERT_ENDPOINT")
            .ok();
        let token = config
            .get_secret::<String>("SECURITY_PROMPT_BERT_TOKEN")
            .ok();

        tracing::debug!(
            model_name = ?model_name,
            has_endpoint = endpoint.is_some(),
            has_token = token.is_some(),
            "Initializing ML detector from config"
        );

        let client = match (model_name, endpoint) {
            (Some(model), endpoint_opt) => {
                tracing::info!(
                    model_name = %model,
                    has_endpoint = endpoint_opt.is_some(),
                    "Using model-based configuration"
                );
                ClassificationClient::from_model_name(&model, endpoint_opt, token, None)?
            }
            (None, Some(endpoint_url)) => {
                tracing::info!(
                    endpoint = %endpoint_url,
                    "Using direct endpoint configuration"
                );
                ClassificationClient::new(endpoint_url, None, token)?
            }
            (None, None) => {
                anyhow::bail!(
                    "ML detection requires either SECURITY_PROMPT_BERT_MODEL (for model mapping) \
                     or SECURITY_PROMPT_BERT_ENDPOINT (for direct endpoint configuration)"
                )
            }
        };

        Ok(Self::new(client))
    }

    pub async fn scan(&self, text: &str) -> Result<f32> {
        tracing::debug!(
            text_length = text.len(),
            text_preview = %text.chars().take(100).collect::<String>(),
            "ML detection scanning text"
        );

        let score = self.client.classify(text).await?;

        tracing::info!(
            score = %score,
            "ML detection result"
        );

        Ok(score)
    }
}
