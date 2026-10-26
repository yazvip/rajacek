use std::{
    env,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
    time::Instant,
};

use anyhow::{Context, Result};
use rajacek_api::{config::AppConfig, database::Database, models::UsageEvent};
use redis::{
    aio::ConnectionManager,
    streams::{StreamId, StreamKey, StreamReadReply},
};
use tokio::time::sleep;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;

const DEFAULT_GROUP: &str = "rajacek-ledger";
const DEAD_LETTER_SUFFIX: &str = ":dead-letter";

/// B15 (audit 2026-10-25): satu event yang gagal persist selamanya dulu
/// memblokir seluruh ledger (head-of-line blocking) karena loop selalu
/// membaca pending dulu dan error persist menggagalkan sesi. Setelah
/// percobaan persist per-event sebanyak ini, event dipindahkan ke DLQ +
/// ACK seperti payload malformed, sehingga event fresh bisa jalan lagi.
/// N=5: cukup untuk melewati gangguan DB sesaat (sesi retry tiap 3 detik,
/// jadi 5 percobaan ~= 15 detik + waktu proses), kecil untuk menahan
/// antrean. Penghitung hidup di main() agar selamat dari restart sesi
/// (sesi baru dibuat tiap gagal); restart proses me-reset hitungan, yang
/// hanya memberi event beracun 5 percobaan tambahan — dapat diterima.
const MAX_PERSIST_ATTEMPTS: u32 = 5;

/// B14 (audit 2026-10-25): ambang alarm panjang stream. MAXLEN di
/// enqueue sudah membatasi stream ke ~100.000 entri, jadi alarm ini
/// adalah jaring pengaman visibilitas (bukan pencegah): bila XLEN
/// melewati 80.000 (~60 MB), ada yang salah dengan laju/retensi dan
/// operator harus melihat sebelum cap tercapai.
const STREAM_LENGTH_WARN_THRESHOLD: u64 = 80_000;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = AppConfig::from_env()?;
    let database_url = config
        .database_url
        .as_deref()
        .context("DATABASE_URL wajib tersedia untuk menjalankan worker")?;
    let redis_url = config
        .redis_url
        .as_deref()
        .context("REDIS_URL wajib tersedia untuk menjalankan worker")?;
    let stream_name = config.event_stream_name;
    let group = env::var("WORKER_CONSUMER_GROUP").unwrap_or_else(|_| DEFAULT_GROUP.to_owned());
    let consumer = env::var("WORKER_CONSUMER_NAME")
        .unwrap_or_else(|_| format!("worker-{}", Uuid::now_v7().simple()));

    let database = Database::connect(database_url).await?;
    if environment_flag("AUTO_MIGRATE") {
        database.migrate().await?;
        tracing::info!("Migrasi MySQL selesai dijalankan oleh worker");
    }

    tracing::info!(
        stream = %stream_name,
        group = %group,
        consumer = %consumer,
        "Worker ledger Rajacek dimulai"
    );

    // K48 (retensi target mentah 90 hari, D5): prune periodik — sekali
    // saat startup, lalu tiap 24 jam. Tiap tick mem-NULL-kan target_raw
    // + account_name baris > 90 hari dalam batch 1.000 (maks 10 batch
    // per tick agar satu tick tidak menahan transaksi lama); baris
    // riwayat TIDAK dihapus. Salinan Redis stream + DLQ mengandalkan
    // cap yang sudah ada (bukan prune ini).
    let prune_pool = database.pool().clone();
    tokio::spawn(async move {
        loop {
            // Log tiap tick TERMASUK 0 baris: tanpa ini, tick yang
            // berjalan normal tidak bisa dibedakan dari task prune
            // yang tidak pernah jalan (verifikasi K48 mengandalkan
            // baris log ini + query COUNT sisa baris mentah > 90 hari).
            let mut tick_pruned = 0u64;
            for _ in 0..10 {
                match rajacek_api::store::AdminStore::prune_old_raw_targets(&prune_pool, 1_000)
                    .await
                {
                    Ok(0) => break,
                    Ok(pruned) => {
                        tick_pruned += pruned;
                        if pruned < 1_000 {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            "Prune retensi target mentah K48 gagal; dicoba lagi pada tick berikutnya"
                        );
                        break;
                    }
                }
            }
            tracing::info!(
                pruned = tick_pruned,
                "Prune retensi target mentah K48 selesai (tick 24 jam)"
            );
            sleep(Duration::from_secs(24 * 3_600)).await;
        }
    });

    // Penghitung percobaan persist B15: sengaja di luar loop sesi agar
    // tidak me-reset tiap sesi worker gagal dan dimulai ulang.
    let mut persist_attempts = PersistAttempts::new();

    loop {
        match run_consumer_session(
            redis_url,
            &stream_name,
            &group,
            &consumer,
            &database,
            &mut persist_attempts,
        )
        .await
        {
            Ok(()) => tracing::warn!("Sesi worker selesai tanpa alasan; menyambung kembali"),
            Err(error) => tracing::error!(error = ?error, "Sesi worker gagal; mencoba kembali"),
        }
        sleep(Duration::from_secs(3)).await;
    }
}

/// Penghitung percobaan persist per stream-id, murni dan dapat diuji
/// tanpa Redis/DB (lihat tes di bawah). Hanya kegagalan per-event yang
/// dihitung; kegagalan koneksi DB TIDAK PERNAH dihitung (lihat
/// process_reply: gerbang health check), karena saat DB mati semua pesan
/// gagal dan menghitungnya akan mem-DLQ seluruh antrean.
#[derive(Default)]
struct PersistAttempts {
    counts: std::collections::HashMap<String, u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistAction {
    /// Coba lagi lewat jalur retry normal (sesi gagal, tidur 3 detik).
    Retry,
    /// Sudah melewati batas: pindahkan ke DLQ + ACK, lanjut ke pesan
    /// berikutnya dalam batch yang sama.
    DeadLetter,
}

impl PersistAttempts {
    fn new() -> Self {
        Self {
            counts: std::collections::HashMap::new(),
        }
    }

    fn record_success(&mut self, stream_id: &str) {
        self.counts.remove(stream_id);
    }

    /// Mengembalikan aksi untuk kegagalan per-event ini beserta jumlah
    /// percobaan sejauh ini (untuk log). Mencapai batas akan membersihkan
    /// hitungan agar kegagalan berikutnya untuk id yang sama (mis. setelah
    /// redelivery) dihitung dari awal lagi.
    fn record_failure(&mut self, stream_id: &str) -> (PersistAction, u32) {
        let count = self.counts.entry(stream_id.to_owned()).or_insert(0);
        *count += 1;
        let attempt = *count;
        if attempt >= MAX_PERSIST_ATTEMPTS {
            self.counts.remove(stream_id);
            (PersistAction::DeadLetter, attempt)
        } else {
            (PersistAction::Retry, attempt)
        }
    }
}

async fn run_consumer_session(
    redis_url: &str,
    stream_name: &str,
    group: &str,
    consumer: &str,
    database: &Database,
    persist_attempts: &mut PersistAttempts,
) -> Result<()> {
    let client = redis::Client::open(redis_url).context("REDIS_URL tidak valid")?;
    let mut connection = ConnectionManager::new(client)
        .await
        .context("Tidak dapat membuka koneksi Redis untuk worker")?;

    ensure_consumer_group(&mut connection, stream_name, group).await?;
    let dead_letter_stream = format!("{stream_name}{DEAD_LETTER_SUFFIX}");
    // Reclaim immediately on start (orphans from previous random-named
    // consumers), then once a minute.
    let mut last_reclaim = Instant::now() - Duration::from_secs(61);

    loop {
        if last_reclaim.elapsed() >= Duration::from_secs(60) {
            last_reclaim = Instant::now();
            if let Err(error) = reclaim_dead_consumers(
                &mut connection,
                stream_name,
                group,
                consumer,
                &dead_letter_stream,
                database,
                persist_attempts,
            )
            .await
            {
                tracing::warn!(?error, "Reclaim pesan consumer mati gagal; dicoba lagi pada siklus berikutnya");
            }
            // Alarm B14: XLEN O(1) sekali per menit di siklus yang sudah
            // ada; tidak ditambahkan ke jalur enqueue yang panas.
            warn_if_stream_too_long(&mut connection, stream_name).await;
            // B26 (Fase 3): alarm DLQ di siklus yang sama — panel
            // membaca panjang DLQ langsung dari Redis, jadi alert
            // Telegram di sini hanya saluran kedua, bukan satu-satunya
            // jejak. Berbasis transisi (kosong -> tidak kosong) agar
            // DLQ yang menetap tidak membanjiri chat tiap menit.
            warn_if_dlq_non_empty(&mut connection, &dead_letter_stream).await;
        }
        // Retry messages still pending for this named consumer before accepting new work. A
        // stable WORKER_CONSUMER_NAME preserves these retries through ordinary restarts.
        let pending = read_group(&mut connection, stream_name, group, consumer, "0", false).await?;
        // A "0" read always returns the stream key, even with zero pending ids;
        // only actual ids count as pending work. Checking keys alone here looped
        // forever on the pending branch and fresh events were never read.
        let has_pending = pending.keys.iter().any(|key| !key.ids.is_empty());
        if has_pending {
            process_reply(
                &mut connection,
                stream_name,
                &dead_letter_stream,
                group,
                &pending,
                database,
                persist_attempts,
            )
            .await?;
            continue;
        }

        let fresh = read_group(&mut connection, stream_name, group, consumer, ">", true).await?;
        process_reply(
            &mut connection,
            stream_name,
            &dead_letter_stream,
            group,
            &fresh,
            database,
            persist_attempts,
        )
        .await?;
    }
}

/// Claim pending messages left by dead consumers (audit 2026-10-25, Q-B7).
/// A consumer that died (restart with a new random name, crash) used to
/// leave its un-ACKed messages in the PEL forever: charged events could
/// then vanish from validation_requests/history. Messages idle > 5 minutes
/// under any other consumer are claimed by us and processed through the
/// normal path (idempotent inserts + ACK), so recovery is safe.
async fn reclaim_dead_consumers(
    connection: &mut ConnectionManager,
    stream_name: &str,
    group: &str,
    consumer: &str,
    dead_letter_stream: &str,
    database: &Database,
    persist_attempts: &mut PersistAttempts,
) -> Result<()> {
    // XPENDING summary: [total, min-id, max-id, [[consumer, count], ...]].
    let pending: redis::Value = redis::cmd("XPENDING")
        .arg(stream_name)
        .arg(group)
        .query_async(connection)
        .await
        .context("XPENDING gagal")?;
    let consumers = match &pending {
        redis::Value::Array(parts) if parts.len() >= 4 => match &parts[3] {
            redis::Value::Array(list) => list
                .iter()
                .filter_map(|entry| match entry {
                    redis::Value::Array(pair) if !pair.is_empty() => {
                        redis::from_redis_value::<String>(&pair[0]).ok()
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    for other in consumers {
        if other == consumer {
            continue;
        }
        // XAUTOCLAIM: [next-start-id, [[id, [field, value, ...]], ...]].
        let claimed: redis::Value = redis::cmd("XAUTOCLAIM")
            .arg(stream_name)
            .arg(group)
            .arg(consumer)
            .arg(300_000)
            .arg("0-0")
            .arg("COUNT")
            .arg(32)
            .query_async(connection)
            .await
            .context("XAUTOCLAIM gagal")?;
        let reply = xautoclaim_to_reply(stream_name, &claimed)?;
        let count: usize = reply.keys.iter().map(|key| key.ids.len()).sum();
        if count > 0 {
            tracing::info!(from_consumer = %other, count, "Mengklaim pesan consumer mati");
            process_reply(
                connection,
                stream_name,
                dead_letter_stream,
                group,
                &reply,
                database,
                persist_attempts,
            )
            .await?;
        }
    }
    Ok(())
}

fn xautoclaim_to_reply(stream_name: &str, value: &redis::Value) -> Result<StreamReadReply> {
    use std::collections::HashMap;
    let mut ids = Vec::new();
    if let redis::Value::Array(parts) = value {
        if let Some(redis::Value::Array(messages)) = parts.get(1) {
            for message in messages {
                if let redis::Value::Array(message_parts) = message {
                    let Some(id) = message_parts
                        .first()
                        .and_then(|v| redis::from_redis_value::<String>(v).ok())
                    else {
                        continue;
                    };
                    let mut map = HashMap::new();
                    if let Some(redis::Value::Array(fields)) = message_parts.get(1) {
                        for pair in fields.chunks(2) {
                            if let [key, val] = pair {
                                if let Ok(key) = redis::from_redis_value::<String>(key) {
                                    map.insert(key, val.clone());
                                }
                            }
                        }
                    }
                    ids.push(StreamId { id, map });
                }
            }
        }
    }
    Ok(StreamReadReply {
        keys: vec![StreamKey {
            key: stream_name.to_owned(),
            ids,
        }],
    })
}

async fn ensure_consumer_group(
    connection: &mut ConnectionManager,
    stream_name: &str,
    group: &str,
) -> Result<()> {
    let result: redis::RedisResult<String> = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(stream_name)
        .arg(group)
        .arg("0")
        .arg("MKSTREAM")
        .query_async(connection)
        .await;

    match result {
        Ok(_) => {
            tracing::info!(stream = %stream_name, group = %group, "Consumer group Redis dibuat");
            Ok(())
        }
        Err(error) if error.code() == Some("BUSYGROUP") => Ok(()),
        Err(error) => Err(error).context("Gagal membuat consumer group Redis"),
    }
}

async fn read_group(
    connection: &mut ConnectionManager,
    stream_name: &str,
    group: &str,
    consumer: &str,
    cursor: &str,
    block: bool,
) -> Result<StreamReadReply> {
    let mut command = redis::cmd("XREADGROUP");
    command
        .arg("GROUP")
        .arg(group)
        .arg(consumer)
        .arg("COUNT")
        .arg(32);
    if block {
        command.arg("BLOCK").arg(5_000);
    }
    command.arg("STREAMS").arg(stream_name).arg(cursor);
    command
        .query_async(connection)
        .await
        .context("Gagal membaca event dari Redis Stream")
}

async fn process_reply(
    connection: &mut ConnectionManager,
    stream_name: &str,
    dead_letter_stream: &str,
    group: &str,
    reply: &StreamReadReply,
    database: &Database,
    persist_attempts: &mut PersistAttempts,
) -> Result<()> {
    for stream in &reply.keys {
        for message in &stream.ids {
            let payload = match message.map.get("payload") {
                Some(value) => match redis::from_redis_value::<String>(value) {
                    Ok(payload) => payload,
                    Err(error) => {
                        dead_letter(
                            connection,
                            dead_letter_stream,
                            stream_name,
                            &message.id,
                            "payload_bukan_string",
                            None,
                        )
                        .await?;
                        acknowledge(connection, stream_name, group, &message.id).await?;
                        tracing::warn!(error = ?error, stream_id = %message.id, "Event tanpa payload string dipindahkan ke dead letter");
                        continue;
                    }
                },
                None => {
                    dead_letter(
                        connection,
                        dead_letter_stream,
                        stream_name,
                        &message.id,
                        "payload_tidak_ditemukan",
                        None,
                    )
                    .await?;
                    acknowledge(connection, stream_name, group, &message.id).await?;
                    tracing::warn!(stream_id = %message.id, "Event tanpa payload dipindahkan ke dead letter");
                    continue;
                }
            };

            let event = match serde_json::from_str::<UsageEvent>(&payload) {
                Ok(event) => event,
                Err(error) => {
                    dead_letter(
                        connection,
                        dead_letter_stream,
                        stream_name,
                        &message.id,
                        "payload_json_tidak_valid",
                        Some(&payload),
                    )
                    .await?;
                    acknowledge(connection, stream_name, group, &message.id).await?;
                    tracing::warn!(error = ?error, stream_id = %message.id, "Event JSON tidak valid dipindahkan ke dead letter");
                    continue;
                }
            };

            // B15: bedakan kegagalan koneksi DB dari kegagalan per-event.
            // Taksonomi error sqlx tidak dapat diandalkan untuk membedakan
            // paket error server MySQL (mis. koneksi putus di tengah
            // transaksi) dari error per-event (lebar kolom/tipe data), jadi
            // pembedanya adalah probe liveness: SELECT 1 yang murah, hanya
            // di jalur gagal (bukan di jalur panas).
            //
            // - Probe gagal -> DB tidak terjangkau: pesan tetap pending dan
            //   TIDAK dihitung. Ini yang benar saat DB mati, karena kalau
            //   tidak, seluruh antrean akan ter-DLQ satu per satu.
            // - Probe sukses -> DB hidup, jadi kegagalan ini spesifik untuk
            //   event ini: hitung. Di bawah batas, perilaku lama dipertahankan
            //   persis (sesi gagal, tidur 3 detik, baca pending dulu). Pada
            //   batas, event di-DLQ + ACK seperti payload malformed dan loop
            //   LANJUT ke pesan berikutnya dalam batch yang sama — inilah
            //   yang memecah head-of-line blocking. Urutan baca pending-dulu
            //   di run_consumer_session TIDAK diubah: pesan fresh tetap
            //   menunggu sampai pending habis, tapi pending yang beracun kini
            //   akhirnya habis juga. Perilaku payload malformed (DLQ + ACK
            //   langsung, tanpa hitungan) TIDAK diubah.
            match database
                .persist_usage_event(&event)
                .await
                .with_context(|| format!("Gagal menyimpan event {} ke MySQL", event.event_id))
            {
                Ok(()) => {
                    persist_attempts.record_success(&message.id);
                    acknowledge(connection, stream_name, group, &message.id).await?;
                    tracing::info!(
                        stream_id = %message.id,
                        event_id = %event.event_id,
                        request_id = %event.request_id,
                        product = event.product.as_str(),
                        "Event penggunaan dipersistenkan dan diakui"
                    );
                }
                Err(error) => {
                    if database.health_check().await.is_err() {
                        tracing::warn!(
                            error = ?error,
                            stream_id = %message.id,
                            "MySQL tidak terjangkau saat persist; pesan tetap pending dan tidak dihitung menuju dead letter"
                        );
                        return Err(error);
                    }
                    let (action, attempt) = persist_attempts.record_failure(&message.id);
                    match action {
                        PersistAction::Retry => {
                            tracing::warn!(
                                error = ?error,
                                stream_id = %message.id,
                                attempt,
                                max_attempts = MAX_PERSIST_ATTEMPTS,
                                "Persist event gagal; dicoba lagi sebelum dead letter"
                            );
                            return Err(error);
                        }
                        PersistAction::DeadLetter => {
                            dead_letter(
                                connection,
                                dead_letter_stream,
                                stream_name,
                                &message.id,
                                "persist_gagal_berulang",
                                Some(&payload),
                            )
                            .await?;
                            acknowledge(connection, stream_name, group, &message.id).await?;
                            tracing::error!(
                                stream_id = %message.id,
                                event_id = %event.event_id,
                                attempts = attempt,
                                "Event gagal persist berulang kali dipindahkan ke dead letter; periksa DLQ dan perbaiki data/kolom, lalu replay manual bila perlu"
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

async fn acknowledge(
    connection: &mut ConnectionManager,
    stream_name: &str,
    group: &str,
    stream_id: &str,
) -> Result<()> {
    redis::cmd("XACK")
        .arg(stream_name)
        .arg(group)
        .arg(stream_id)
        .query_async::<i64>(connection)
        .await
        .context("Gagal mengakui event Redis Stream")?;
    Ok(())
}

async fn dead_letter(
    connection: &mut ConnectionManager,
    dead_letter_stream: &str,
    source_stream: &str,
    source_id: &str,
    reason: &str,
    payload: Option<&str>,
) -> Result<()> {
    let safe_payload = payload.unwrap_or("");
    // Retensi DLQ dibatasi seperti stream utama (B14): DLQ hanya terisi
    // oleh event malformed/beracun yang langka, jadi 10.000 entri jauh
    // lebih dari cukup untuk investigasi tanpa membiarkan DLQ tumbuh
    // tanpa batas bila terjadi banjir event beracun.
    redis::cmd("XADD")
        .arg(dead_letter_stream)
        .arg("MAXLEN")
        .arg("~")
        .arg(10_000)
        .arg("*")
        .arg("source_stream")
        .arg(source_stream)
        .arg("source_id")
        .arg(source_id)
        .arg("reason")
        .arg(reason)
        .arg("payload")
        .arg(safe_payload)
        .query_async::<String>(connection)
        .await
        .context("Gagal memindahkan event ke dead letter stream")?;
    Ok(())
}

/// Alarm B14: log warn bila panjang stream melewati ambang. Tidak pernah
/// fatal dan tidak pernah memangkas sendiri — pemangkasan sudah ditangani
/// MAXLEN di enqueue; alarm ini hanya memastikan operator melihat laju
/// abnormal sebelum cap tercapai.
async fn warn_if_stream_too_long(connection: &mut ConnectionManager, stream_name: &str) {
    let length: redis::RedisResult<i64> = redis::cmd("XLEN")
        .arg(stream_name)
        .query_async(connection)
        .await;
    match length {
        Ok(length) if length > STREAM_LENGTH_WARN_THRESHOLD as i64 => {
            tracing::warn!(
                stream = %stream_name,
                length,
                threshold = STREAM_LENGTH_WARN_THRESHOLD,
                "Panjang stream validasi melewati ambang alarm; periksa laju event dan retensi MAXLEN"
            );
            // AREA 3 trigger (c): memakai ambang alarm yang SUDAH ADA
            // (80.000, sekali per menit di siklus yang sudah ada) —
            // tidak ada ambang baru. Tanpa env Telegram, alert() hanya
            // menulis log (worker tidak memegang handle store admin,
            // jadi tidak ada baris aktivitas admin dari jalur ini).
            rajacek_api::alerts::alert(
                "Antrean stream validasi melewati ambang",
                &format!(
                    "Panjang stream {stream_name} = {length} (ambang {threshold}); periksa laju event dan retensi MAXLEN.",
                    threshold = STREAM_LENGTH_WARN_THRESHOLD
                ),
            );
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(?error, "Gagal membaca XLEN untuk alarm panjang stream");
        }
    }
}

/// Status alert DLQ terakhir di proses worker ini: true bila alert
/// "DLQ tidak kosong" sudah dikirim sejak DLQ terakhir kosong. Reset
/// saat DLQ kembali kosong, sehingga pengisian berikutnya meng-alert
/// lagi tepat sekali. Murni transisi — bukan penghitung.
static DLQ_ALERT_SENT: AtomicBool = AtomicBool::new(false);

/// Alarm B26: alert SEKALI saat DLQ bertransisi kosong -> tidak kosong
/// (sekali per menit di siklus yang sudah ada, XLEN O(1)). Panel
/// menampilkan DLQ secara live dari Redis; alert ini hanya saluran
/// kedua. DLQ yang menetap tidak mengulang alert sampai ia sempat
/// kosong lagi.
async fn warn_if_dlq_non_empty(connection: &mut ConnectionManager, dead_letter_stream: &str) {
    let length: redis::RedisResult<i64> = redis::cmd("XLEN")
        .arg(dead_letter_stream)
        .query_async(connection)
        .await;
    match length {
        Ok(length) if length > 0 => {
            if !DLQ_ALERT_SENT.swap(true, Ordering::SeqCst) {
                tracing::warn!(
                    stream = %dead_letter_stream,
                    length,
                    "Dead-letter tidak kosong; operator dapat me-replay dari panel monitor"
                );
                rajacek_api::alerts::alert(
                    "Antrean dead-letter tidak kosong",
                    &format!(
                        "Dead-letter {dead_letter_stream} berisi {length} event; buka panel monitor untuk melihat dan me-replay."
                    ),
                );
            }
        }
        Ok(_) => {
            DLQ_ALERT_SENT.store(false, Ordering::SeqCst);
        }
        Err(error) => {
            tracing::warn!(?error, "Gagal membaca XLEN DLQ untuk alarm");
        }
    }
}

fn environment_flag(name: &str) -> bool {
    matches!(
        env::var(name)
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "rajacek_worker=info,sqlx=warn,redis=warn".into());
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();
}

#[cfg(test)]
mod tests {
    use super::{PersistAction, PersistAttempts, MAX_PERSIST_ATTEMPTS};

    #[test]
    fn persist_attempts_retry_below_threshold_then_dead_letter_at_threshold() {
        let mut attempts = PersistAttempts::new();
        for expected in 1..MAX_PERSIST_ATTEMPTS {
            let (action, attempt) = attempts.record_failure("1792938536390-0");
            assert_eq!(action, PersistAction::Retry);
            assert_eq!(attempt, expected);
        }
        let (action, attempt) = attempts.record_failure("1792938536390-0");
        assert_eq!(action, PersistAction::DeadLetter);
        assert_eq!(attempt, MAX_PERSIST_ATTEMPTS);
    }

    #[test]
    fn persist_attempts_success_clears_count() {
        let mut attempts = PersistAttempts::new();
        attempts.record_failure("1792938536390-0");
        attempts.record_failure("1792938536390-0");
        attempts.record_success("1792938536390-0");
        let (action, attempt) = attempts.record_failure("1792938536390-0");
        assert_eq!(action, PersistAction::Retry);
        assert_eq!(attempt, 1);
    }

    #[test]
    fn persist_attempts_dead_letter_clears_count_for_redelivery() {
        let mut attempts = PersistAttempts::new();
        for _ in 0..MAX_PERSIST_ATTEMPTS {
            attempts.record_failure("1792938536390-0");
        }
        // Setelah DLQ, redelivery id yang sama (bila ada) dihitung dari awal.
        let (action, attempt) = attempts.record_failure("1792938536390-0");
        assert_eq!(action, PersistAction::Retry);
        assert_eq!(attempt, 1);
    }

    #[test]
    fn persist_attempts_ids_are_counted_independently() {
        let mut attempts = PersistAttempts::new();
        for _ in 0..MAX_PERSIST_ATTEMPTS {
            attempts.record_failure("id-beracun");
        }
        let (action, attempt) = attempts.record_failure("id-sehat");
        assert_eq!(action, PersistAction::Retry);
        assert_eq!(attempt, 1);
    }
}
