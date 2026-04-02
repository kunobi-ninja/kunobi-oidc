/// Static token authentication (for CI, scripts, service accounts).
pub struct StaticTokenAuth {
    token: String,
}

impl StaticTokenAuth {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}
