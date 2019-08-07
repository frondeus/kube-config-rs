use std::path::Path;
use openssl::{
    pkcs12::Pkcs12,
    pkey::PKey,
    x509::X509,
};
use failure::ResultExt;
use crate::{Result, Error, ErrorKind};
use crate::apis::{AuthInfo, Cluster, Config, Context};

/// KubeConfigLoader loads current context, cluster, and authentication information.
#[derive(Debug)]
pub struct KubeConfigLoader {
    pub current_context: Context,
    pub cluster: Cluster,
    pub user: AuthInfo,
}

impl KubeConfigLoader {
    pub fn load<P: AsRef<Path>>(
        path: P,
        context: Option<String>,
        cluster: Option<String>,
        user: Option<String>,
    ) -> Result<KubeConfigLoader> {
        let config = Config::load_config(path)?;
        let context_name = context.as_ref().unwrap_or(&config.current_context);
        let current_context = config
            .contexts
            .iter()
            .find(|named_context| &named_context.name == context_name)
            .map(|named_context| &named_context.context)
            .ok_or_else(|| ErrorKind::KubeConfig("Unable to load current context".into()))?;
        let cluster_name = cluster.as_ref().unwrap_or(&current_context.cluster);
        let cluster = config
            .clusters
            .iter()
            .find(|named_cluster| &named_cluster.name == cluster_name)
            .map(|named_cluster| &named_cluster.cluster)
            .ok_or_else(|| ErrorKind::KubeConfig("Unable to load cluster of context".into()))?;
        let user_name = user.as_ref().unwrap_or(&current_context.user);
        let user = config
            .auth_infos
            .iter()
            .find(|named_user| &named_user.name == user_name)
            .map(|named_user| {
                let mut user = named_user.auth_info.clone();
                match user.load_gcp() {
                    Ok(_) => Ok(user),
                    Err(e) => Err(e),
                }
            })
            .ok_or_else(|| ErrorKind::KubeConfig("Unable to load user of context".into()))??;
        Ok(KubeConfigLoader {
            current_context: current_context.clone(),
            cluster: cluster.clone(),
            user: user.clone(),
        })
    }

    pub fn p12(&self, password: &str) -> Result<Pkcs12> {
        let client_cert = &self.user.load_client_certificate()?;
        let client_key = &self.user.load_client_key()?;

        let x509 = X509::from_pem(&client_cert).context(ErrorKind::SslError)?;
        let pkey = PKey::private_key_from_pem(&client_key).context(ErrorKind::SslError)?;

        Ok(Pkcs12::builder()
            .build(password, "kubeconfig", &pkey, &x509)
            .context(ErrorKind::SslError)?)
    }

    pub fn ca(&self) -> Option<Result<X509>> {
        let ca = self.cluster.load_certificate_authority().ok()?;
        Some(X509::from_pem(&ca).map_err(|_| Error::from(ErrorKind::SslError)))
    }
}
