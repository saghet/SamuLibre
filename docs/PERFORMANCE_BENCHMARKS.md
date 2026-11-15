# Performance Benchmarks

## Mediciones Reales Observadas
- **Enumeración de conexiones TCP/UDP (IPv4 + IPv6) vía `iphlpapi.dll`**: `452` sockets enumerados y enriquecidos en `5.48 ms` (sin spawn de `netstat.exe`).
- **Caché de hashes SHA-256**: TTL de 60 segundos con límite acotado (`2048` entradas) para evitar re-lectura de ejecutables en cada ciclo de monitoreo.
- **Caché DNS TTL**: Límite acotado de `4096` entradas en memoria.
- **Rotación de Logs**: `event_logs` acotado a `1000` entradas, `query_logs` a `500` entradas y `correlation_events` a `200` entradas.
