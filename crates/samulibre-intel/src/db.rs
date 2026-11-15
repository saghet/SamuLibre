use crate::models::{
    IndicatorHistoryEntry, IndicatorType, IntelSource, IntelStats, ThreatIndicatorRecord,
    ValidationStatus,
};
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Almacén centralizado SQLite para SamuLibre Threat Intelligence Engine
pub struct IntelDatabase {
    conn: Connection,
    db_path: PathBuf,
}

impl IntelDatabase {
    /// Abre o inicializa la base de datos central en la ruta indicada
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self> {
        let p = db_path.as_ref().to_path_buf();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("No se pudo crear directorio {:?}", parent))?;
        }
        let conn = Connection::open(&p)
            .with_context(|| format!("No se pudo abrir base SQLite {:?}", p))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let db = Self { conn, db_path: p };
        db.init_schema()?;
        Ok(db)
    }

    /// Abre una base de datos en memoria para pruebas unitarias
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn,
            db_path: PathBuf::from(":memory:"),
        };
        db.init_schema()?;
        Ok(db)
    }

    pub fn path(&self) -> &Path {
        &self.db_path
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS indicators (
                id TEXT PRIMARY KEY,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL,
                payload TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                malware_family TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                category TEXT NOT NULL,
                source_name TEXT NOT NULL,
                repo_origin TEXT NOT NULL,
                rule_author TEXT NOT NULL,
                license TEXT NOT NULL,
                source_url TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_modified TEXT NOT NULL,
                expires_at TEXT,
                confidence INTEGER NOT NULL,
                validation_status TEXT NOT NULL,
                validation_score INTEGER NOT NULL,
                validation_notes TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                external_vars TEXT NOT NULL DEFAULT '[]',
                required_modules TEXT NOT NULL DEFAULT '[]'
            );

            CREATE INDEX IF NOT EXISTS idx_indicators_type_status
                ON indicators(indicator_type, validation_status);
            CREATE INDEX IF NOT EXISTS idx_indicators_content_hash
                ON indicators(content_hash);
            CREATE INDEX IF NOT EXISTS idx_indicators_source_url
                ON indicators(source_url);
            CREATE INDEX IF NOT EXISTS idx_indicators_repo
                ON indicators(repo_origin);
            CREATE INDEX IF NOT EXISTS idx_indicators_value
                ON indicators(value);

            CREATE TABLE IF NOT EXISTS indicator_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id TEXT NOT NULL,
                action TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                old_status TEXT,
                new_status TEXT,
                changed_at TEXT NOT NULL,
                details TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_history_indicator
                ON indicator_history(indicator_id);

            CREATE TABLE IF NOT EXISTS sources (
                source_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                url TEXT NOT NULL,
                last_sync_at TEXT,
                last_commit TEXT,
                status TEXT NOT NULL,
                received_count INTEGER NOT NULL DEFAULT 0,
                accepted_count INTEGER NOT NULL DEFAULT 0,
                rejected_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                response_time_ms INTEGER NOT NULL DEFAULT 0,
                license_default TEXT NOT NULL DEFAULT 'Unknown'
            );
            ",
        )?;
        Ok(())
    }

    /// Calcula un ID determinista para evitar colisiones entre fuentes y reglas
    pub fn compute_indicator_id(
        indicator_type: IndicatorType,
        repo_origin: &str,
        value: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(indicator_type.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(repo_origin.as_bytes());
        hasher.update(b"|");
        hasher.update(value.as_bytes());
        hex::encode(&hasher.finalize()[..16])
    }

    /// Comprueba si ya existe un indicador activo con el mismo `content_hash` en otro ID (duplicado)
    pub fn find_duplicate_by_content_hash(
        &self,
        indicator_type: IndicatorType,
        content_hash: &str,
        exclude_id: &str,
    ) -> Result<Option<String>> {
        let res: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM indicators
                 WHERE indicator_type = ?1 AND content_hash = ?2 AND id != ?3
                   AND validation_status != 'OBSOLETA'
                 LIMIT 1",
                params![indicator_type.as_str(), content_hash, exclude_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(res)
    }

    /// Inserta o actualiza un indicador registrando automáticamente el historial de cambios
    /// Retorna `Ok(UpsertOutcome)` indicando si fue nuevo, modificado o sin cambios
    pub fn upsert_indicator(&self, record: &ThreatIndicatorRecord) -> Result<UpsertOutcome> {
        let now = Utc::now().to_rfc3339();
        let existing: Option<(String, String, u32)> = self
            .conn
            .query_row(
                "SELECT content_hash, validation_status, version FROM indicators WHERE id = ?1",
                params![record.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        let ext_json = serde_json::to_string(&record.external_vars)?;
        let mod_json = serde_json::to_string(&record.required_modules)?;

        match existing {
            None => {
                self.conn.execute(
                    "INSERT INTO indicators (
                        id, indicator_type, value, payload, content_hash,
                        malware_family, threat_name, category, source_name, repo_origin,
                        rule_author, license, source_url, first_seen, last_modified,
                        expires_at, confidence, validation_status, validation_score,
                        validation_notes, version, external_vars, required_modules
                    ) VALUES (
                        ?1, ?2, ?3, ?4, ?5,
                        ?6, ?7, ?8, ?9, ?10,
                        ?11, ?12, ?13, ?14, ?15,
                        ?16, ?17, ?18, ?19,
                        ?20, ?21, ?22, ?23
                    )",
                    params![
                        record.id,
                        record.indicator_type.as_str(),
                        record.value,
                        record.payload,
                        record.content_hash,
                        record.malware_family,
                        record.threat_name,
                        record.category,
                        record.source_name,
                        record.repo_origin,
                        record.rule_author,
                        record.license,
                        record.source_url,
                        record.first_seen,
                        record.last_modified,
                        record.expires_at,
                        record.confidence as i64,
                        record.validation_status.as_str(),
                        record.validation_score as i64,
                        record.validation_notes,
                        record.version as i64,
                        ext_json,
                        mod_json,
                    ],
                )?;

                self.conn.execute(
                    "INSERT INTO indicator_history (
                        indicator_id, action, old_hash, new_hash, old_status, new_status, changed_at, details
                    ) VALUES (?1, 'INSERTED', NULL, ?2, NULL, ?3, ?4, ?5)",
                    params![
                        record.id,
                        record.content_hash,
                        record.validation_status.as_str(),
                        now,
                        format!("Incorporado desde {}", record.source_name),
                    ],
                )?;
                Ok(UpsertOutcome::Inserted)
            }
            Some((old_hash, old_status, old_version)) => {
                let new_status_str = record.validation_status.as_str();
                if old_hash == record.content_hash && old_status == new_status_str {
                    return Ok(UpsertOutcome::Unchanged);
                }
                let next_version = old_version + 1;
                self.conn.execute(
                    "UPDATE indicators SET
                        value = ?2, payload = ?3, content_hash = ?4,
                        malware_family = ?5, threat_name = ?6, category = ?7,
                        source_name = ?8, repo_origin = ?9, rule_author = ?10,
                        license = ?11, source_url = ?12, last_modified = ?13,
                        expires_at = ?14, confidence = ?15, validation_status = ?16,
                        validation_score = ?17, validation_notes = ?18, version = ?19,
                        external_vars = ?20, required_modules = ?21
                     WHERE id = ?1",
                    params![
                        record.id,
                        record.value,
                        record.payload,
                        record.content_hash,
                        record.malware_family,
                        record.threat_name,
                        record.category,
                        record.source_name,
                        record.repo_origin,
                        record.rule_author,
                        record.license,
                        record.source_url,
                        now,
                        record.expires_at,
                        record.confidence as i64,
                        new_status_str,
                        record.validation_score as i64,
                        record.validation_notes,
                        next_version as i64,
                        ext_json,
                        mod_json,
                    ],
                )?;

                let action = if old_hash != record.content_hash {
                    "MODIFIED"
                } else {
                    "STATUS_CHANGED"
                };
                self.conn.execute(
                    "INSERT INTO indicator_history (
                        indicator_id, action, old_hash, new_hash, old_status, new_status, changed_at, details
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        record.id,
                        action,
                        old_hash,
                        record.content_hash,
                        old_status,
                        new_status_str,
                        now,
                        record.validation_notes,
                    ],
                )?;
                Ok(UpsertOutcome::Updated)
            }
        }
    }

    /// Marca como OBSOLETA las reglas pertenecientes a un archivo eliminado o retirado de un repositorio
    pub fn mark_source_url_obsolete(&self, repo_origin: &str, source_url: &str) -> Result<usize> {
        let now = Utc::now().to_rfc3339();
        let mut stmt = self.conn.prepare(
            "SELECT id, content_hash, validation_status FROM indicators
             WHERE repo_origin = ?1 AND source_url = ?2 AND validation_status != 'OBSOLETA'",
        )?;
        let rows: Vec<(String, String, String)> = stmt
            .query_map(params![repo_origin, source_url], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let count = rows.len();
        for (id, hash, old_status) in rows {
            self.conn.execute(
                "UPDATE indicators SET validation_status = 'OBSOLETA', last_modified = ?2, validation_notes = 'Archivo eliminado o retirado en repositorio origen' WHERE id = ?1",
                params![id, now],
            )?;
            self.conn.execute(
                "INSERT INTO indicator_history (indicator_id, action, old_hash, new_hash, old_status, new_status, changed_at, details)
                 VALUES (?1, 'RETIRED', ?2, ?2, ?3, 'OBSOLETA', ?4, 'Regla retirada en sincronización incremental')",
                params![id, hash, old_status, now],
            )?;
        }
        Ok(count)
    }

    /// Inserta o actualiza el estado de una fuente en la tabla `sources`
    pub fn upsert_source(&self, source: &IntelSource) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sources (
                source_id, name, source_kind, url, last_sync_at, last_commit,
                status, received_count, accepted_count, rejected_count,
                last_error, response_time_ms, license_default
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            ON CONFLICT(source_id) DO UPDATE SET
                name = excluded.name,
                source_kind = excluded.source_kind,
                url = excluded.url,
                last_sync_at = excluded.last_sync_at,
                last_commit = COALESCE(excluded.last_commit, sources.last_commit),
                status = excluded.status,
                received_count = excluded.received_count,
                accepted_count = excluded.accepted_count,
                rejected_count = excluded.rejected_count,
                last_error = excluded.last_error,
                response_time_ms = excluded.response_time_ms,
                license_default = excluded.license_default",
            params![
                source.source_id,
                source.name,
                source.source_kind,
                source.url,
                source.last_sync_at,
                source.last_commit,
                source.status,
                source.received_count as i64,
                source.accepted_count as i64,
                source.rejected_count as i64,
                source.last_error,
                source.response_time_ms as i64,
                source.license_default,
            ],
        )?;
        Ok(())
    }

    pub fn get_source(&self, source_id: &str) -> Result<Option<IntelSource>> {
        self.conn
            .query_row(
                "SELECT source_id, name, source_kind, url, last_sync_at, last_commit,
                        status, received_count, accepted_count, rejected_count,
                        last_error, response_time_ms, license_default
                 FROM sources WHERE source_id = ?1",
                params![source_id],
                |row| {
                    Ok(IntelSource {
                        source_id: row.get(0)?,
                        name: row.get(1)?,
                        source_kind: row.get(2)?,
                        url: row.get(3)?,
                        last_sync_at: row.get(4)?,
                        last_commit: row.get(5)?,
                        status: row.get(6)?,
                        received_count: row.get::<_, i64>(7)? as usize,
                        accepted_count: row.get::<_, i64>(8)? as usize,
                        rejected_count: row.get::<_, i64>(9)? as usize,
                        last_error: row.get(10)?,
                        response_time_ms: row.get::<_, i64>(11)? as u64,
                        license_default: row.get(12)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Carga todas las reglas YARA aprobadas para compilación en el motor de producción
    pub fn load_production_yara_rules(&self) -> Result<Vec<ThreatIndicatorRecord>> {
        self.load_indicators_by_query(
            "SELECT id, indicator_type, value, payload, content_hash,
                    malware_family, threat_name, category, source_name, repo_origin,
                    rule_author, license, source_url, first_seen, last_modified,
                    expires_at, confidence, validation_status, validation_score,
                    validation_notes, version, external_vars, required_modules
             FROM indicators
             WHERE indicator_type = 'yara_rule'
               AND validation_status IN ('APROBADA', 'APROBADA_CON_RESTRICCIONES')",
        )
    }

    /// Carga todas las reglas de comportamiento aprobadas para el motor EDR/BehaviorMonitor
    pub fn load_production_behavior_rules(&self) -> Result<Vec<ThreatIndicatorRecord>> {
        self.load_indicators_by_query(
            "SELECT id, indicator_type, value, payload, content_hash,
                    malware_family, threat_name, category, source_name, repo_origin,
                    rule_author, license, source_url, first_seen, last_modified,
                    expires_at, confidence, validation_status, validation_score,
                    validation_notes, version, external_vars, required_modules
             FROM indicators
             WHERE indicator_type = 'behavior_rule'
               AND validation_status IN ('APROBADA', 'APROBADA_CON_RESTRICCIONES')",
        )
    }

    /// Carga todos los hashes SHA-256 aprobados para el motor de escaneo
    pub fn load_production_sha256_hashes(&self) -> Result<Vec<(String, String, String, u8)>> {
        let mut stmt = self.conn.prepare(
            "SELECT value, threat_name, category, confidence FROM indicators
             WHERE indicator_type = 'sha256'
               AND validation_status IN ('APROBADA', 'APROBADA_CON_RESTRICCIONES')",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)? as u8,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Carga todas las IPs C2 aprobadas para NetDefense / Firewall
    pub fn load_production_c2_ips(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT value FROM indicators
             WHERE indicator_type = 'c2_ip'
               AND validation_status IN ('APROBADA', 'APROBADA_CON_RESTRICCIONES')",
        )?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Carga dominios y URLs maliciosas aprobadas para Protección Web / DNS Proxy
    pub fn load_production_web_indicators(&self) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT indicator_type, value, threat_name FROM indicators
             WHERE indicator_type IN ('domain', 'url')
               AND validation_status IN ('APROBADA', 'APROBADA_CON_RESTRICCIONES')",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lista todas las fuentes registradas en la base central
    pub fn list_sources(&self) -> Result<Vec<IntelSource>> {
        let mut stmt = self.conn.prepare(
            "SELECT source_id, name, source_kind, url, last_sync_at, last_commit,
                    status, received_count, accepted_count, rejected_count,
                    last_error, response_time_ms, license_default
             FROM sources ORDER BY name ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(IntelSource {
                    source_id: row.get(0)?,
                    name: row.get(1)?,
                    source_kind: row.get(2)?,
                    url: row.get(3)?,
                    last_sync_at: row.get(4)?,
                    last_commit: row.get(5)?,
                    status: row.get(6)?,
                    received_count: row.get::<_, i64>(7)? as usize,
                    accepted_count: row.get::<_, i64>(8)? as usize,
                    rejected_count: row.get::<_, i64>(9)? as usize,
                    last_error: row.get(10)?,
                    response_time_ms: row.get::<_, i64>(11)? as u64,
                    license_default: row.get(12)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Devuelve una vista ligera de indicadores aprobados para el explorador de UI sin cargar payloads pesados
    pub fn list_catalog_preview(
        &self,
        limit_per_type: usize,
    ) -> Result<Vec<(String, String, String, String, String)>> {
        let mut out = Vec::new();
        for (db_type, ui_kind) in [
            ("sha256", "SHA256"),
            ("yara_rule", "YARA"),
            ("behavior_rule", "BEHAVIOR"),
            ("c2_ip", "C2_IP"),
            ("domain", "DOMAIN"),
            ("url", "URL"),
        ] {
            let mut stmt = self.conn.prepare(
                "SELECT value, COALESCE(NULLIF(threat_name, ''), malware_family, value), source_name, last_modified
                 FROM indicators
                 WHERE indicator_type = ?1 AND validation_status IN ('APROBADA', 'APROBADA_CON_RESTRICCIONES')
                 ORDER BY last_modified DESC
                 LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(params![db_type, limit_per_type as i64], |row| {
                    Ok((
                        ui_kind.to_string(),
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            out.extend(rows);
        }
        Ok(out)
    }

    /// Paginación SQLite real (sin truncamiento) con filtros por tipo, entorno de validación y búsqueda
    pub fn query_catalog_paginated(
        &self,
        kind: &str,
        status_filter: &str,
        query: &str,
        page: usize,
        page_size: usize,
    ) -> Result<crate::models::CatalogPageResult> {
        let mut conditions: Vec<String> = Vec::new();
        let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();

        match kind.to_ascii_uppercase().as_str() {
            "SHA256" => conditions.push("indicator_type = 'sha256'".to_string()),
            "YARA" => conditions.push("indicator_type = 'yara_rule'".to_string()),
            "BEHAVIOR" | "SIGMA" => conditions.push("indicator_type = 'behavior_rule'".to_string()),
            "LOLDRIVERS" => conditions.push("repo_origin LIKE '%LOLDrivers%'".to_string()),
            "C2_IP" => conditions.push("indicator_type = 'c2_ip'".to_string()),
            "DOMAIN" => conditions.push("indicator_type = 'domain'".to_string()),
            "URL" => conditions.push("indicator_type = 'url'".to_string()),
            "NETWORK" | "RED" => {
                conditions.push("indicator_type IN ('c2_ip', 'domain', 'url')".to_string())
            }
            _ => {}
        }

        match status_filter.to_ascii_uppercase().as_str() {
            "OBSERVACION" | "EN_OBSERVACION" => {
                conditions.push("validation_status = 'EN_OBSERVACION'".to_string());
            }
            "LABORATORIO" => {
                conditions.push("validation_status = 'LABORATORIO'".to_string());
            }
            "RECHAZADA" => {
                conditions.push("validation_status = 'RECHAZADA'".to_string());
            }
            "OBSOLETA" => {
                conditions.push("validation_status = 'OBSOLETA'".to_string());
            }
            "ALL_STATUS" | "TODAS" => {}
            _ => {
                conditions.push(
                    "validation_status IN ('APROBADA', 'APROBADA_CON_RESTRICCIONES')".to_string(),
                );
            }
        }

        let trimmed_q = query.trim().to_ascii_lowercase();
        if !trimmed_q.is_empty() {
            let pattern = format!("%{}%", trimmed_q);
            let idx = params_vec.len() + 1;
            conditions.push(format!(
                "(lower(value) LIKE ?{0} OR lower(threat_name) LIKE ?{0} OR lower(malware_family) LIKE ?{0} OR lower(source_name) LIKE ?{0} OR lower(license) LIKE ?{0})",
                idx
            ));
            params_vec.push(rusqlite::types::Value::Text(pattern));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let count_sql = format!("SELECT COUNT(*) FROM indicators {}", where_clause);
        let total_filtered = self.conn.query_row(
            &count_sql,
            rusqlite::params_from_iter(params_vec.iter()),
            |r| r.get::<_, i64>(0),
        )? as usize;

        let limit = page_size.max(1) as i64;
        let offset = (page * page_size.max(1)) as i64;
        let lim_idx = params_vec.len() + 1;
        let off_idx = params_vec.len() + 2;
        params_vec.push(rusqlite::types::Value::Integer(limit));
        params_vec.push(rusqlite::types::Value::Integer(offset));

        let select_sql = format!(
            "SELECT indicator_type, value, COALESCE(NULLIF(threat_name, ''), malware_family, value),
                    source_name, last_modified, license, source_url, rule_author,
                    validation_status, validation_score
             FROM indicators
             {}
             ORDER BY last_modified DESC, id ASC
             LIMIT ?{} OFFSET ?{}",
            where_clause, lim_idx, off_idx
        );

        let mut stmt = self.conn.prepare(&select_sql)?;
        let entries = stmt
            .query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
                let db_type: String = row.get(0)?;
                let ui_kind = match db_type.as_str() {
                    "sha256" => "SHA256",
                    "yara_rule" => "YARA",
                    "behavior_rule" => "BEHAVIOR",
                    "c2_ip" => "C2_IP",
                    "domain" => "DOMAIN",
                    "url" => "URL",
                    other => other,
                }
                .to_string();
                Ok(crate::models::CatalogEntryRow {
                    kind: ui_kind,
                    identifier: row.get(1)?,
                    family: row.get(2)?,
                    source: row.get(3)?,
                    added_at: row.get(4)?,
                    license: row.get(5)?,
                    source_url: row.get(6)?,
                    rule_author: row.get(7)?,
                    validation_status: row.get(8)?,
                    validation_score: row.get::<_, i64>(9)? as u8,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(crate::models::CatalogPageResult {
            total_filtered,
            entries,
        })
    }

    fn load_indicators_by_query(&self, sql: &str) -> Result<Vec<ThreatIndicatorRecord>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt
            .query_map([], |row| {
                let ext_str: String = row.get(21)?;
                let mod_str: String = row.get(22)?;
                Ok(ThreatIndicatorRecord {
                    id: row.get(0)?,
                    indicator_type: IndicatorType::from_str(&row.get::<_, String>(1)?)
                        .unwrap_or(IndicatorType::YaraRule),
                    value: row.get(2)?,
                    payload: row.get(3)?,
                    content_hash: row.get(4)?,
                    malware_family: row.get(5)?,
                    threat_name: row.get(6)?,
                    category: row.get(7)?,
                    source_name: row.get(8)?,
                    repo_origin: row.get(9)?,
                    rule_author: row.get(10)?,
                    license: row.get(11)?,
                    source_url: row.get(12)?,
                    first_seen: row.get(13)?,
                    last_modified: row.get(14)?,
                    expires_at: row.get(15)?,
                    confidence: row.get::<_, i64>(16)? as u8,
                    validation_status: ValidationStatus::from_str(&row.get::<_, String>(17)?),
                    validation_score: row.get::<_, i64>(18)? as u8,
                    validation_notes: row.get(19)?,
                    version: row.get::<_, i64>(20)? as u32,
                    external_vars: serde_json::from_str(&ext_str).unwrap_or_default(),
                    required_modules: serde_json::from_str(&mod_str).unwrap_or_default(),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Obtiene estadísticas reales agregadas desde la base SQLite
    pub fn get_stats(&self) -> Result<IntelStats> {
        let mut stats = IntelStats::default();
        let mut stmt = self.conn.prepare(
            "SELECT indicator_type, validation_status, COUNT(*)
             FROM indicators
             GROUP BY indicator_type, validation_status",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)? as usize,
            ))
        })?;

        for row in rows {
            let (itype, status, count) = row?;
            stats.total_indicators += count;
            match itype.as_str() {
                "sha256" if status == "APROBADA" || status == "APROBADA_CON_RESTRICCIONES" => {
                    stats.sha256_approved += count;
                }
                "yara_rule" => {
                    stats.yara_total += count;
                    match status.as_str() {
                        "LABORATORIO" => stats.yara_lab += count,
                        "APROBADA" => stats.yara_approved += count,
                        "APROBADA_CON_RESTRICCIONES" => stats.yara_restricted += count,
                        "EN_OBSERVACION" => stats.yara_observation += count,
                        "RECHAZADA" => stats.yara_rejected += count,
                        "OBSOLETA" => stats.yara_obsolete += count,
                        _ => {}
                    }
                }
                "c2_ip" if status == "APROBADA" || status == "APROBADA_CON_RESTRICCIONES" => {
                    stats.c2_ips_approved += count;
                }
                "domain" if status == "APROBADA" || status == "APROBADA_CON_RESTRICCIONES" => {
                    stats.domains_approved += count;
                }
                "url" if status == "APROBADA" || status == "APROBADA_CON_RESTRICCIONES" => {
                    stats.urls_approved += count;
                }
                "behavior_rule"
                    if status == "APROBADA" || status == "APROBADA_CON_RESTRICCIONES" =>
                {
                    stats.behavior_rules_approved += count;
                }
                _ => {}
            }
        }

        stats.connected_sources = self.conn.query_row(
            "SELECT COUNT(*) FROM sources WHERE status = 'OK'",
            [],
            |r| r.get::<_, i64>(0),
        )? as usize;

        stats.loldrivers_count = self.conn.query_row(
            "SELECT COUNT(*) FROM indicators WHERE repo_origin LIKE '%LOLDrivers%' AND validation_status IN ('APROBADA', 'APROBADA_CON_RESTRICCIONES')",
            [],
            |r| r.get::<_, i64>(0),
        )? as usize;

        Ok(stats)
    }

    pub fn get_history_for_indicator(&self, indicator_id: &str) -> Result<Vec<IndicatorHistoryEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, indicator_id, action, old_hash, new_hash, old_status, new_status, changed_at, details
             FROM indicator_history WHERE indicator_id = ?1 ORDER BY id DESC",
        )?;
        let rows = stmt
            .query_map(params![indicator_id], |r| {
                Ok(IndicatorHistoryEntry {
                    id: r.get(0)?,
                    indicator_id: r.get(1)?,
                    action: r.get(2)?,
                    old_hash: r.get(3)?,
                    new_hash: r.get(4)?,
                    old_status: r.get(5)?,
                    new_status: r.get(6)?,
                    changed_at: r.get(7)?,
                    details: r.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Promueve o cambia el estado de un indicador dejando trazabilidad en `indicator_history`
    pub fn update_validation_status(
        &self,
        indicator_id: &str,
        new_status: ValidationStatus,
        details: &str,
    ) -> Result<bool> {
        let current: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT content_hash, validation_status FROM indicators WHERE id = ?1",
                params![indicator_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((content_hash, old_status)) = current else {
            return Ok(false);
        };
        if old_status == new_status.as_str() {
            return Ok(false);
        }
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE indicators SET validation_status = ?1, validation_notes = ?2, last_modified = ?3 WHERE id = ?4",
            params![new_status.as_str(), details, now, indicator_id],
        )?;
        self.conn.execute(
            "INSERT INTO indicator_history (
                indicator_id, action, old_hash, new_hash, old_status, new_status, changed_at, details
            ) VALUES (?1, 'STATUS_TRANSITION', ?2, ?2, ?3, ?4, ?5, ?6)",
            params![
                indicator_id,
                content_hash,
                old_status,
                new_status.as_str(),
                now,
                details
            ],
        )?;
        Ok(true)
    }

    /// Carga el mapa de hashes SHA-256 de drivers vulnerables/maliciosos (LOLDrivers)
    pub fn load_loldrivers_sha256_map(&self) -> Result<std::collections::HashMap<String, (String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT lower(value), COALESCE(NULLIF(threat_name, ''), malware_family, 'LOLDriver'), source_url
             FROM indicators
             WHERE indicator_type = 'sha256'
               AND repo_origin LIKE '%LOLDrivers%'
               AND validation_status IN ('APROBADA', 'APROBADA_CON_RESTRICCIONES')",
        )?;
        let mut map = std::collections::HashMap::new();
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (h, name, url) = row?;
            map.insert(h, (name, url));
        }
        Ok(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    Inserted,
    Updated,
    Unchanged,
}
