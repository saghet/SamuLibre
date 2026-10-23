use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};

/// Representa un Honey-Token o trampa de credenciales desplegada en el sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneyCredential {
    pub name: String,
    pub path: String,
    pub token_type: String,
    pub original_hash: String,
}

pub struct CredentialShield {
    honey_tokens: HashMap<PathBuf, HoneyCredential>,
}

impl CredentialShield {
    pub fn new() -> Self {
        Self {
            honey_tokens: HashMap::new(),
        }
    }

    /// Despliega señuelos de credenciales atractivos para troyanos InfoStealers (RedLine, Vidar, Lumma, Mimikatz)
    pub fn deploy_honey_tokens(&mut self, base_dir: impl AsRef<Path>) -> std::io::Result<usize> {
        let dir = base_dir.as_ref();
        let _ = fs::create_dir_all(dir);

        let decoys = [
            ("aws_credentials_backup.ini", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE_HONEY\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY_HONEY", "CloudCredential"),
            ("ssh_id_rsa_decoy", "-----BEGIN OPENSSH PRIVATE KEY-----\nHONEY_TOKEN_TRIPWIRE_SAMULIBRE_KEY_UNAUTHORIZED_ACCESS_ALERT\n-----END OPENSSH PRIVATE KEY-----", "SSHKey"),
            ("database_root_passwords.kdbx", "HONEY_KEEPASS_VAULT_TRIGGER_ALERT_SAMULIBRE", "PasswordVault"),
        ];

        let mut count = 0;
        for (filename, content, ttype) in decoys {
            let path = dir.join(filename);
            fs::write(&path, content)?;

            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let hash = hex::encode(hasher.finalize());

            self.honey_tokens.insert(
                path.clone(),
                HoneyCredential {
                    name: filename.to_string(),
                    path: path.to_string_lossy().to_string(),
                    token_type: ttype.to_string(),
                    original_hash: hash,
                },
            );
            count += 1;
        }

        Ok(count)
    }

    /// Verifica si un proceso no autorizado ha intentado leer o alterar un señuelo de credenciales
    pub fn check_honey_tokens(&self) -> Vec<HoneyCredential> {
        let mut tripped = Vec::new();
        for (path, token) in &self.honey_tokens {
            match fs::read(path) {
                Ok(bytes) => {
                    let mut hasher = Sha256::new();
                    hasher.update(&bytes);
                    let curr_hash = hex::encode(hasher.finalize());
                    if curr_hash != token.original_hash {
                        tripped.push(token.clone());
                    }
                }
                Err(_) => {
                    // Si el archivo fue eliminado o movido, también se considera violado
                    tripped.push(token.clone());
                }
            }
        }
        tripped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deploy_and_check_honey_tokens() {
        let tmp_dir = std::env::temp_dir().join("samulibre_honey_test");
        let mut shield = CredentialShield::new();
        let deployed = shield.deploy_honey_tokens(&tmp_dir).unwrap();
        assert!(deployed >= 3);

        // Sin modificaciones, nada activado
        let tripped = shield.check_honey_tokens();
        assert!(tripped.is_empty());

        // Simulamos alteración de un honey-token
        let sample = tmp_dir.join("aws_credentials_backup.ini");
        let _ = fs::write(&sample, "tampered");
        let tripped_after = shield.check_honey_tokens();
        assert_eq!(tripped_after.len(), 1);

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
