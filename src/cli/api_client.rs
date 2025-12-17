use reqwest::{Client, Response};

pub struct ApiClient {
    base_url: String,
    client: Client,
}

impl ApiClient {
    pub fn from_host_port(host: &str, port: u16) -> Self {
        let base_url = format!("http://{}:{}/api/v1", host, port);
        let client = Client::new();
        Self { base_url, client }
    }

    pub fn with_client(host: &str, port: u16, client: Client) -> Self {
        let base_url = format!("http://{}:{}/api/v1", host, port);
        Self { base_url, client }
    }

    pub async fn get_status(&self) -> reqwest::Result<Response> {
        self.client
            .get(format!("{}/status", self.base_url))
            .send()
            .await
    }

    pub async fn get_version(&self) -> reqwest::Result<Response> {
        self.client
            .get(format!("{}/version", self.base_url))
            .send()
            .await
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
        self.client
            .post(format!("{}{}", self.base_url, path))
            .json(req)
            .send()
            .await
    }

    pub async fn get_policies(&self, raw: bool) -> reqwest::Result<Response> {
        let url = if raw {
            format!("{}/policies?format=raw", self.base_url)
        } else {
            format!("{}/policies", self.base_url)
        };
        self.client.get(url).send().await
    }

    pub async fn post_policies_raw(
        &self,
        token: &str,
        content: String,
    ) -> reqwest::Result<Response> {
        self.client
            .post(format!("{}/policies", self.base_url))
            .header("Content-Type", "text/plain")
            .header("X-Upload-Token", token)
            .body(content)
            .send()
            .await
    }

    pub async fn post_policies_json(&self, content: String) -> reqwest::Result<Response> {
        #[derive(serde::Serialize)]
        struct Upload {
            policies: String,
        }
        self.client
            .post(format!("{}/policies", self.base_url))
            .json(&Upload { policies: content })
            .send()
            .await
    }

    pub async fn get_user_policies(&self, user: &str) -> reqwest::Result<Response> {
        self.client
            .get(format!("{}/policies/{}", self.base_url, user))
            .send()
            .await
    }
}
