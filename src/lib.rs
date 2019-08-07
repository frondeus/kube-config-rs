mod apis;
mod exec;
mod incluster_config;
mod kube_config;
mod utils;
mod oauth2;

use base64;
use failure::{Fail, Context, Backtrace, ResultExt};
use std::fmt::{self, Display};
use reqwest::r#async::Client;
use reqwest::{Certificate, Identity, header};
use crate::kube_config::KubeConfigLoader;

type Result<T> = ::core::result::Result<T, Error>;

#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Error loading kube config: {}", _0)]
    KubeConfig(String),

    #[fail(display = "Error deserializing response")]
    SslError,
}

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }
    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}
impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error { inner: Context::new(kind) }
    }
}
impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}

/// Configuration stores kubernetes path
#[derive(Clone)]
pub struct Configuration {
    pub base_path: String,
    pub client: Client
}

impl Configuration {
    pub fn new(base_path: String, client: Client) -> Self {
        Self { base_path, client }
    }

    /// Returns a config includes authentication and cluster infomation from kubeconfig file.
    ///
    /// # Example
    /// ```no_run
    /// use kube_config::Configuration;
    ///
    /// let kubeconfig = Configuration::load()
    ///     .expect("failed to load kubeconfig");
    /// ```
    pub fn load() -> Result<Self> {
        Self::load_with(Default::default())
    }

    /// Returns a config includes authentication and cluster information from kubeconfig file.
    ///
    /// # Example
    /// ```no_run
    /// use kube_config::Configuration;
    ///
    /// let kubeconfig = config::load_kube_config()
    ///     .expect("failed to load kubeconfig");
    /// ```
    pub fn load_with(options: ConfigOptions) -> Result<Self> {
        let kubeconfig = utils::kubeconfig_path()
            .or_else(utils::default_kube_path)
            .ok_or_else(|| ErrorKind::KubeConfig("Unable to load file".into()))?;

        let loader =
            KubeConfigLoader::load(kubeconfig, options.context, options.cluster, options.user)?;
        let token = match &loader.user.token {
            Some(token) => Some(token.clone()),
            None => {
                if let Some(exec) = &loader.user.exec {
                    let creds = exec::auth_exec(exec)?;
                    let status = creds
                        .status
                        .ok_or_else(|| ErrorKind::KubeConfig("exec-plugin response did not contain a status".into()))?;
                    status.token
                } else {
                    None
                }
            }
        };

        let mut client_builder = Client::builder();

        if let Some(ca) = loader.ca() {
            let req_ca = Certificate::from_der(&ca?.to_der().context(ErrorKind::SslError)?)
                .context(ErrorKind::SslError)?;
            client_builder = client_builder.add_root_certificate(req_ca);
        }
        match loader.p12(" ") {
            Ok(p12) => {
                let req_p12 = Identity::from_pkcs12_der(&p12.to_der().context(ErrorKind::SslError)?, " ")
                    .context(ErrorKind::SslError)?;
                client_builder = client_builder.identity(req_p12);
            }
            Err(_) => {
                // last resort only if configs ask for it, and no client certs
                if let Some(true) = loader.cluster.insecure_skip_tls_verify {
                    client_builder = client_builder.danger_accept_invalid_certs(true);
                }
            }
        }

        let mut headers = header::HeaderMap::new();

        match (
            utils::data_or_file(&token, &loader.user.token_file),
            (loader.user.username, loader.user.password),
        ) {
            (Ok(token), _) => {
                headers.insert(
                    header::AUTHORIZATION,
                    header::HeaderValue::from_str(&format!("Bearer {}", token))
                        .context(ErrorKind::KubeConfig("Invalid bearer token".to_string()))?,
                );
            }
            (_, (Some(u), Some(p))) => {
                let encoded = base64::encode(&format!("{}:{}", u, p));
                headers.insert(
                    header::AUTHORIZATION,
                    header::HeaderValue::from_str(&format!("Basic {}", encoded))
                        .context(ErrorKind::KubeConfig("Invalid bearer token".to_string()))?,
                );
            }
            _ => {}
        }

        let client_builder = client_builder.default_headers(headers);

        let client = client_builder.build()
            .context(ErrorKind::KubeConfig("Unable to build client".to_string()))?;
        Ok(Configuration::new(
            loader.cluster.server,
                client
        ))
    }

    pub fn in_cluster() -> Result<Self> {
        let server = incluster_config::kube_server().ok_or_else(||
            Error::from(ErrorKind::KubeConfig(format!(
                "Unable to load incluster config, {} and {} must be defined",
                incluster_config::SERVICE_HOSTENV,
                incluster_config::SERVICE_PORTENV
            ))))?;

        let ca = incluster_config::load_cert().context(ErrorKind::SslError)?;
        let req_ca = Certificate::from_der(&ca.to_der().context(ErrorKind::SslError)?)
            .context(ErrorKind::SslError)?;

        let token = incluster_config::load_token()
            .context(ErrorKind::KubeConfig("Unable to load in cluster token".to_string()))?;

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", token))
                .context(ErrorKind::KubeConfig("Invalid bearer token".to_string()))?,
        );

        let client_builder = Client::builder()
            .add_root_certificate(req_ca)
            .default_headers(headers);

        let client = client_builder.build()
            .context(ErrorKind::KubeConfig("Unable to build client".to_string()))?;
        Ok(Configuration::new(
            server, client
        ))}
}

/// ConfigOptions stores options used when loading kubeconfig file.
#[derive(Default)]
pub struct ConfigOptions {
    pub context: Option<String>,
    pub cluster: Option<String>,
    pub user:    Option<String>
}

