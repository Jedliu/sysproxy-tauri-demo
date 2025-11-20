use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::RwLock;

pub struct CertManager {
    #[allow(dead_code)]
    ca_cert: Arc<Certificate>,
    #[allow(dead_code)]
    ca_cert_der: Vec<u8>,
    #[allow(dead_code)]
    ca_cert_pem: String,
    #[allow(dead_code)]
    ca_key_pem: String,
    #[allow(dead_code)]
    cert_cache: Arc<RwLock<std::collections::HashMap<String, Arc<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>>>>,
}

impl CertManager {
    /// Create a new certificate manager with a generated or loaded CA certificate
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let cert_dir = Self::get_cert_dir()?;
        fs::create_dir_all(&cert_dir)?;

        let ca_cert_path = cert_dir.join("ca.crt");
        let ca_key_path = cert_dir.join("ca.key");

        let (ca_cert, ca_cert_der, ca_cert_pem, ca_key_pem) = if ca_cert_path.exists() && ca_key_path.exists() {
            // Load existing CA certificate
            let cert_pem = fs::read_to_string(&ca_cert_path)?;
            let key_pem = fs::read_to_string(&ca_key_path)?;

            let key_pair = KeyPair::from_pem(&key_pem)?;
            let params = CertificateParams::from_ca_cert_pem(&cert_pem, key_pair)?;
            let cert = Certificate::from_params(params)?;
            let cert_der = cert.serialize_der()?;

            (cert, cert_der, cert_pem, key_pem)
        } else {
            // Generate new CA certificate
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.distinguished_name = DistinguishedName::new();
            params.distinguished_name.push(DnType::CommonName, "Sysproxy MITM CA");
            params.distinguished_name.push(DnType::OrganizationName, "Sysproxy");
            params.distinguished_name.push(DnType::CountryName, "CN");

            // Set validity period (10 years)
            let not_before = time::OffsetDateTime::now_utc();
            let not_after = not_before + time::Duration::days(3650);
            params.not_before = not_before;
            params.not_after = not_after;

            let cert = Certificate::from_params(params)?;
            let cert_der = cert.serialize_der()?;
            let cert_pem = cert.serialize_pem()?;
            let key_pem = cert.serialize_private_key_pem();

            // Save CA certificate and key
            fs::write(&ca_cert_path, &cert_pem)?;
            fs::write(&ca_key_path, &key_pem)?;

            (cert, cert_der, cert_pem, key_pem)
        };

        Ok(Self {
            ca_cert: Arc::new(ca_cert),
            ca_cert_der,
            ca_cert_pem,
            ca_key_pem,
            cert_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
        })
    }

    /// Get the directory where certificates are stored
    pub fn get_cert_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| "Cannot find home directory")?;
        Ok(PathBuf::from(home).join(".sysproxy").join("certs"))
    }

    /// Get the CA certificate in PEM format
    #[allow(dead_code)]
    pub fn get_ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Get the path to the CA certificate file
    pub fn get_ca_cert_path(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(Self::get_cert_dir()?.join("ca.crt"))
    }

    /// Generate a certificate for a specific domain
    #[allow(dead_code)]
    pub fn generate_cert_for_domain(
        &self,
        domain: &str,
    ) -> Result<Arc<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, Box<dyn std::error::Error>> {
        // Check cache first
        {
            let cache = self.cert_cache.read();
            if let Some(cert) = cache.get(domain) {
                return Ok(Arc::clone(cert));
            }
        }

        // Generate new certificate
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, domain);

        // Add SANs
        params.subject_alt_names = vec![
            SanType::DnsName(domain.to_string().try_into()?),
        ];

        // If domain is an IP address, add it as IP SAN
        if let Ok(ip) = domain.parse::<std::net::IpAddr>() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        }

        // Set validity period (1 year)
        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + time::Duration::days(365);
        params.not_before = not_before;
        params.not_after = not_after;

        let cert = Certificate::from_params(params)?;
        let cert_der = cert.serialize_der_with_signer(&self.ca_cert)?;

        // Convert to rustls types
        let cert_der_owned = CertificateDer::from(cert_der.clone());
        let ca_der_owned = CertificateDer::from(self.ca_cert_der.clone());
        let key_der = PrivateKeyDer::try_from(cert.serialize_private_key_der())?;

        let cert_chain = vec![cert_der_owned, ca_der_owned];
        let result = Arc::new((cert_chain, key_der));

        // Cache the certificate
        {
            let mut cache = self.cert_cache.write();
            cache.insert(domain.to_string(), Arc::clone(&result));
        }

        Ok(result)
    }
}
