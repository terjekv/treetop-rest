use reqwest::{Client, RequestBuilder, Response};
use url::form_urlencoded;

const CORRELATION_HEADER: &str = "x-correlation-id";

/// Percent-encode a string for use in a URL path segment
fn encode_path_segment(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

pub struct ApiClient {
    base_url: String,
    client: Client,
    correlation_id: Option<String>,
}

impl ApiClient {
    pub fn from_host_port(host: &str, port: u16) -> Self {
        let base_url = format!("http://{}:{}/api/v1", host, port);
        let client = Client::new();
        Self {
            base_url,
            client,
            correlation_id: None,
        }
    }

    pub fn with_client(host: &str, port: u16, client: Client) -> Self {
        let base_url = format!("http://{}:{}/api/v1", host, port);
        Self {
            base_url,
            client,
            correlation_id: None,
        }
    }

    pub fn set_correlation_id(&mut self, id: String) {
        self.correlation_id = Some(id);
    }

    fn apply_headers(&self, builder: RequestBuilder) -> RequestBuilder {
        if let Some(cid) = &self.correlation_id {
            builder.header(CORRELATION_HEADER, cid)
        } else {
            builder
        }
    }

    pub async fn get_status(&self) -> reqwest::Result<Response> {
        let builder = self.client.get(format!("{}/status", self.base_url));
        self.apply_headers(builder).send().await
    }

    pub async fn get_version(&self) -> reqwest::Result<Response> {
        let builder = self.client.get(format!("{}/version", self.base_url));
        self.apply_headers(builder).send().await
    }

    pub async fn post_check<T: serde::Serialize + ?Sized>(
        &self,
        detailed: bool,
        req: &T,
    ) -> reqwest::Result<Response> {
        let path = if detailed {
            "/check_detailed"
        } else {
            "/check"
        };
        let builder = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(req);
        self.apply_headers(builder).send().await
    }

    pub async fn post_authorize<T: serde::Serialize + ?Sized>(
        &self,
        req: &T,
        detailed: bool,
    ) -> reqwest::Result<Response> {
        let detail_param = if detailed { "full" } else { "brief" };
        let url = format!("{}/authorize?detail={}", self.base_url, detail_param);
        let builder = self.client.post(url).json(req);
        self.apply_headers(builder).send().await
    }

    pub async fn get_policies(&self, raw: bool) -> reqwest::Result<Response> {
        let url = if raw {
            format!("{}/policies?format=raw", self.base_url)
        } else {
            format!("{}/policies", self.base_url)
        };
        let builder = self.client.get(url);
        self.apply_headers(builder).send().await
    }

    pub async fn post_policies_raw(
        &self,
        token: &str,
        content: String,
    ) -> reqwest::Result<Response> {
        let builder = self
            .client
            .post(format!("{}/policies", self.base_url))
            .header("Content-Type", "text/plain")
            .header("X-Upload-Token", token)
            .body(content);
        self.apply_headers(builder).send().await
    }

    pub async fn post_policies_json(&self, content: String) -> reqwest::Result<Response> {
        #[derive(serde::Serialize)]
        struct Upload {
            policies: String,
        }
        let builder = self
            .client
            .post(format!("{}/policies", self.base_url))
            .json(&Upload { policies: content });
        self.apply_headers(builder).send().await
    }

    pub async fn get_user_policies(
        &self,
        principal: &str,
        groups: Vec<String>,
        raw: bool,
    ) -> reqwest::Result<Response> {
        // Parse principal to extract namespace and entity ID
        let parts: Vec<&str> = principal.split("::").collect();

        let (namespace, entity_id) = if parts.len() > 1 {
            // Has namespace: parts[0..-1] are namespace, last part is entity ID
            (parts[0..parts.len() - 1].to_vec(), parts[parts.len() - 1])
        } else {
            // No namespace
            (vec![], parts[0])
        };

        let encoded_user = encode_path_segment(entity_id);
        let mut url = format!("{}/policies/{}", self.base_url, encoded_user);

        // Add namespace and groups as query parameters (array-style)
        let mut params = Vec::new();

        for ns in namespace {
            if ns == "User" || ns == "Group" {
                continue;
            }
            params.push(format!("namespaces[]={}", ns));
        }

        for group in groups {
            params.push(format!("groups[]={}", group));
        }

        if raw {
            params.push("format=raw".to_string());
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let builder = self.client.get(url);
        self.apply_headers(builder).send().await
    }

    pub async fn get_metrics(&self) -> reqwest::Result<Response> {
        // Metrics endpoint is at root level, not under /api/v1
        let metrics_url = self.base_url.replace("/api/v1", "/metrics");
        let builder = self.client.get(metrics_url);
        self.apply_headers(builder).send().await
    }
}
