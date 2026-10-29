(() => {
  "use strict";

  const state = {
    session: null,
    overview: null,
    products: [],
    providers: [],
    banks: [],
    packages: [],
    rateLimits: [],
    apiKeys: [],
    guard: null,
    history: { items: [], total: 0, limit: 25, offset: 0, source: null, loaded: false },
    members: [],
    membersLoaded: false,
    // Tab Trial/Umum (27 Okt 2026): filter tampilan di atas daftar
    // yang sudah dimuat (kombinasi dengan filter q/status/tanggal
    // server). Default: Semua.
    membersTab: "all",
    orders: [],
    ordersPage: { limit: 100, offset: 0 },
    adminActivity: { items: [], total: 0, limit: 50, offset: 0, action: "", actor: "", from: "", to: "", loaded: false },
    analytics: null,
    analyticsDays: 30,
    providerHealth: null,
    adminAccounts: [],
    dashboardLoadError: false,
    managedMemberId: null,
    memberDetail: null,
    memberDetailPage: { limit: 20, offset: 0 },
    rateDefault: null,
    activeView: "overview",
  };

  const viewLabels = {
    overview: "Ringkasan",
    analytics: "Analitik",
    providers: "Endpoint Provider",
    tester: "Tester Layanan",
    products: "Produk API",
    packages: "Paket & Harga",
    "rate-limits": "Rate Limit",
    "api-keys": "Kunci API",
    members: "Member",
    orders: "Order QRIS",
    activity: "Aktivitas",
    admins: "Admin",
    history: "Riwayat Cek",
    settings: "Pengaturan",
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

  class ApiError extends Error {
    constructor(message, status, payload) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.payload = payload;
    }
  }

  function adminToken() {
    return sessionStorage.getItem("rajacek:development-admin-token") || "";
  }

  function apiHeaders(extra = {}) {
    const headers = { Accept: "application/json", ...extra };
    const token = adminToken();
    if (token) headers["x-admin-token"] = token;
    return headers;
  }

  async function api(path, options = {}) {
    const headers = apiHeaders(options.headers || {});
    // Panel admin menampilkan data live: jangan biarkan browser
    // menyajikan GET basi sesudah mutasi (kasus status order yang
    // tampak tak berubah padahal grant sudah jalan).
    const request = { cache: "no-store", ...options, headers };
    if (options.body != null) {
      // Setiap body JSON wajib membawa Content-Type — termasuk yang sudah
      // di-stringify pemanggil (fetch menganggapnya text/plain dan Axum
      // menolaknya 415). Dulu header hanya dipasang untuk body objek.
      headers["Content-Type"] = "application/json";
      request.body = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
    }

    let response;
    try {
      response = await fetch(path, request);
    } catch {
      throw new ApiError("Tidak dapat menghubungi server. Periksa koneksi Anda.", 0, null);
    }

    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json")
      ? await response.json().catch(() => null)
      : null;

    if (!response.ok) {
      const message = payload?.message || `Permintaan gagal (${response.status}).`;
      throw new ApiError(message, response.status, payload);
    }

    return payload;
  }

  function escapeHtml(value) {
    const element = document.createElement("span");
    element.textContent = String(value ?? "");
    return element.innerHTML;
  }

  function formatNumber(value) {
    return new Intl.NumberFormat("id-ID").format(Number(value || 0));
  }

  function formatRupiah(value) {
    return new Intl.NumberFormat("id-ID", {
      style: "currency",
      currency: "IDR",
      maximumFractionDigits: 0,
    }).format(Number(value || 0));
  }

  function formatPercentage(value, suffix = "%") {
    const number = Number(value || 0);
    return `${number > 0 ? "+" : ""}${number.toLocaleString("id-ID", {
      maximumFractionDigits: 1,
    })}${suffix}`;
  }

  // Normalisasi zona yang sama untuk semua pemformat tanggal admin
  // (audit 2026-10-25, K33): API admin mengirim NaiveDateTime tanpa
  // zona (UTC); tanpa 'Z', browser menafsirkannya sebagai waktu lokal
  // sehingga tampil -7 jam (order 20:13 WIB tampil 13:13). Nilai
  // berzona dibiarkan apa adanya.
  function normalizeDateValue(value) {
    return typeof value === "string" && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(value) ? `${value}Z` : value;
  }

  function formatDate(value) {
    if (!value) return "Belum pernah";
    const date = new Date(normalizeDateValue(value));
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat("id-ID", {
      day: "numeric",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(date);
  }

  // Formatter khusus riwayat admin: 2 baris ringkas ("26 Okt 26" /
  // "10:36", detik dibuang dari tampilan) + timestamp lengkap untuk
  // atribut title sel. formatDate global TIDAK diubah (dipakai view
  // lain). Pemformatan manual (bukan Intl untuk jam) agar pemisah jam
  // selalu ":" — Intl id-ID memakai "." ("10.36").
  function formatHistoryDateTime(value) {
    if (!value) return { date: "—", time: "", full: "—" };
    const date = new Date(normalizeDateValue(value));
    if (Number.isNaN(date.getTime())) return { date: "—", time: "", full: "—" };
    const monthsShort = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des"];
    const monthsLong = ["Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli", "Agustus", "September", "Oktober", "November", "Desember"];
    const pad = (n) => String(n).padStart(2, "0");
    return {
      date: `${pad(date.getDate())} ${monthsShort[date.getMonth()]} ${pad(date.getFullYear() % 100)}`,
      time: `${pad(date.getHours())}:${pad(date.getMinutes())}`,
      full: `${date.getDate()} ${monthsLong[date.getMonth()]} ${date.getFullYear()}, ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`,
    };
  }

  function relativeTime(value) {
    if (!value) return "—";
    // K33: relativeTime dulu TIDAK menormalisasi zona, tidak seperti
    // formatDate — aman selama pemakainya berzona, rapuh bila suatu
    // hari field naive dilewatkan. Kini memakai normalisasi yang sama.
    const parsed = new Date(normalizeDateValue(value)).getTime();
    if (Number.isNaN(parsed)) return "—";
    const difference = Date.now() - parsed;
    const seconds = Math.max(0, Math.round(difference / 1000));
    if (seconds < 60) return "baru saja";
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) return `${minutes} mnt lalu`;
    const hours = Math.round(minutes / 60);
    if (hours < 24) return `${hours} jam lalu`;
    const days = Math.round(hours / 24);
    return `${days} hari lalu`;
  }

  function productLabel(product) {
    return {
      bank_account: "Rekening",
      ewallet: "E-wallet",
      whatsapp: "WhatsApp",
      pln: "PLN",
    }[product] || product;
  }

  // Baris kode bank / e-wallet di Detail riwayat (migration 0035):
  // hanya untuk produk bank_account ("Kode bank") dan ewallet
  // ("E-wallet"); produk lain tidak menampilkan baris ini. Hint null
  // (baris lama pra-fitur) -> "tidak tercatat (data lama)", sama
  // seperti Sumber data. Tampilan sudah di-resolve server ("014 · BCA",
  // "dana · DANA"); panel tidak pernah menerima kode upstream.
  function historyHintRow(item) {
    if (item.product !== "bank_account" && item.product !== "ewallet") return "";
    const label = item.product === "bank_account" ? "Kode bank" : "E-wallet";
    const value = item.provider_hint_display ? item.provider_hint_display : "tidak tercatat (data lama)";
    return testerRow(label, value);
  }

  function statusBadge(status) {
    const label = {
      active: "Aktif",
      inactive: "Nonaktif",
      revoked: "Dicabut",
      valid: "Berhasil",
      not_kyc: "Belum KYC",
      pending: "Menunggu",
      operational: "Normal",
      demo: "Demo",
      unknown: "Tidak diukur",
    }[status] || status;
    return `<span class="status-badge ${escapeHtml(status)}">${escapeHtml(label)}</span>`;
  }

  function showToast(message, type = "info") {
    const region = $("#toast-region");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.textContent = message;
    region.append(toast);
    window.setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(8px)";
      window.setTimeout(() => toast.remove(), 220);
    }, 4800);
  }

  // Audit login 2026-10-27, BESAR-4: 401 dan 403 DIPISAH. Hanya 401
  // (sesi habis/tak valid) yang membuang sesi dan membuka login.
  // 403 (sesi sah tapi peran kurang) TETAP di shell: sesi tidak
  // dihapus, tidak ada updateSessionUI/showLoginOnly, hanya toast
  // generik — pesan server tidak dipakai agar detail peran tidak
  // bocor ke toast dan pesannya deterministik.
  function handleApiError(error) {
    if (error instanceof ApiError) {
      if (error.status === 401) {
        state.session = null;
        updateSessionUI();
        showLoginOnly();
      } else if (error.status === 403) {
        showToast("Anda tidak memiliki akses untuk aksi ini.", "error");
        return;
      }
      showToast(error.message, "error");
      return;
    }
    console.error(error);
    showToast("Terjadi kesalahan tak terduga.", "error");
  }

  // Audit login 2026-10-27, BESAR-2 (sisi panel): pemetaan kode
  // ?auth= dari redirect callback gagal (kontrak antar-worker —
  // jangan diubah sepihak). Kode tak dikenal -> pesan generik yang
  // sama dengan failed. Tidak ada detail internal dari parameter
  // yang pernah ditampilkan; nilai parameter hanya dipakai sebagai
  // kunci pemetaan ini.
  function authCallbackMessage(code) {
    switch (code) {
      case "denied":
        return "Akses ditolak: akun ini bukan admin. Silakan pilih akun lain.";
      case "expired":
        return "Sesi login kedaluwarsa. Silakan coba lagi.";
      case "unavailable":
        return "Layanan login tidak tersedia. Coba lagi nanti.";
      case "failed":
        return "Login gagal. Silakan coba lagi.";
      default:
        return "Login gagal. Silakan coba lagi.";
    }
  }

  // Baca ?auth=<kode> bila ada, bersihkan dari URL via replaceState
  // (parameter tidak boleh menetap di URL/histori), kembalikan pesan
  // ramah atau null bila tidak ada parameter. Dipanggil sekali di
  // awal initialize, sebelum pemeriksaan sesi.
  function consumeAuthCallbackParam() {
    let code = null;
    try {
      const url = new URL(window.location.href);
      if (url.searchParams.has("auth")) {
        code = url.searchParams.get("auth");
        url.searchParams.delete("auth");
        window.history.replaceState(null, "", url.toString());
      }
    } catch {
      return null;
    }
    if (code === null || code === "") return null;
    return authCallbackMessage(code);
  }

  // Tampilkan pesan callback di auth-modal (bila elemennya ada).
  // Aman dipanggil kapan pun: bila modal tertutup (sesi sah), pesan
  // tidak terlihat; showAdmin() membersihkannya lagi.
  function showAuthCallbackMessage(message) {
    if (!message) return;
    const element = $("#auth-callback-message");
    if (element) {
      element.textContent = message;
      element.hidden = false;
    }
    const retry = $("#auth-retry-button");
    if (retry) retry.hidden = false;
  }

  function clearAuthCallbackMessage() {
    const element = $("#auth-callback-message");
    if (element) element.hidden = true;
    const retry = $("#auth-retry-button");
    if (retry) retry.hidden = true;
  }

  function openModal(id) {
    const modal = $(`#${id}`);
    if (!modal) return;
    document.body.classList.remove("menu-open");
    $("#modal-backdrop").hidden = false;
    modal.hidden = false;
    document.body.style.overflow = "hidden";
    const focusable = modal.querySelector("input, select, textarea, button, a");
    window.setTimeout(() => focusable?.focus(), 40);
  }

  // Gerbang login admin: selama sesi tidak valid, yang tampil HANYA halaman
  // login — shell dashboard disembunyikan dan modal login tidak bisa ditutup.
  function showLoginOnly() {
    stopHistoryPolling();
    document.body.classList.add("auth-required");
    document.body.classList.remove("auth-ok");
    closeAllModals();
    openModal("auth-modal");
  }

  function showAdmin() {
    document.body.classList.remove("auth-required");
    document.body.classList.add("auth-ok");
    clearAuthCallbackMessage();
    closeModal("auth-modal");
  }

  function closeModal(id) {
    if (id === "auth-modal" && document.body.classList.contains("auth-required")) return;
    const modal = $(`#${id}`);
    if (!modal) return;
    modal.hidden = true;
    const anyOpen = $$(".modal").some((item) => !item.hidden);
    if (!anyOpen) {
      $("#modal-backdrop").hidden = true;
      document.body.style.overflow = "";
    }
  }

  function closeAllModals() {
    $$(".modal").forEach((modal) => {
      if (modal.id === "auth-modal" && document.body.classList.contains("auth-required")) return;
      modal.hidden = true;
    });
    const anyOpen = $$(".modal").some((item) => !item.hidden);
    if (!anyOpen) {
      $("#modal-backdrop").hidden = true;
      document.body.style.overflow = "";
    }
  }

  function updateSessionUI() {
    const session = state.session;
    const name = session?.name || "Administrator";
    const email = session?.email || "Akses belum diverifikasi";
    $("#profile-name").textContent = name;
    $("#profile-name").title = name;
    $("#profile-email").textContent = email;
    $("#profile-email").title = email;
    $("#profile-avatar").textContent = name.trim().slice(0, 1).toUpperCase() || "A";

    const google = $("#google-login-button");
    const developmentForm = $("#development-token-form");
    const localLoginForm = $("#local-login-form");
    const developmentAvailable = Boolean(session?.development_access_available);
    const localLoginAvailable = Boolean(session?.local_login_available);
    google.style.display = session?.google_login_configured ? "inline-flex" : "none";
    developmentForm.hidden = !developmentAvailable;
    localLoginForm.hidden = !localLoginAvailable;

    if (!session?.authenticated && !session?.google_login_configured && !developmentAvailable && !localLoginAvailable) {
      $("#auth-title").textContent = "Akses belum dikonfigurasi.";
    } else {
      $("#auth-title").textContent = "Masuk ke pusat kendali.";
    }
  }

  async function refreshSession() {
    state.session = await api("/v1/auth/session");
    updateSessionUI();
    if (state.session?.authenticated) {
      refreshPinStatus().catch(() => {});
    }
    return state.session;
  }

  // Status PIN administrator untuk banner "PIN masih default".
  // Best-effort: gagal fetch = banner tetap tersembunyi, bukan error.
  async function refreshPinStatus() {
    const status = await api("/v1/admin/pin-status");
    const banner = $("#pin-default-banner");
    if (banner) banner.hidden = !status?.pin_default;
    const chip = $("#pin-status-chip");
    if (chip) {
      chip.textContent = !status?.pin_configured
        ? "Belum diatur"
        : status.pin_default
          ? "Masih default — segera ubah"
          : "Sudah diubah";
    }
    return status;
  }

  function setActiveView(view) {
    if (!viewLabels[view]) return;
    state.activeView = view;
    $$(".view").forEach((element) => {
      element.classList.toggle("is-visible", element.id === `view-${view}`);
    });
    $$(".nav-link[data-view-target]").forEach((element) => {
      element.classList.toggle("is-active", element.dataset.viewTarget === view);
    });
    $("#breadcrumb-title").textContent = viewLabels[view];
    if (view === "history" && !state.history.loaded) loadHistory().catch(handleApiError);
    if (view === "history") startHistoryPolling(); else stopHistoryPolling();
    if (view === "members" && !state.membersLoaded) loadMembers().catch(handleApiError);
    if (view === "activity") loadAdminActivity().catch(handleApiError);
    if (view === "admins") loadAdminAccounts().catch(handleApiError);
    if (view === "orders") loadOrders().catch(handleApiError);
    if (view === "analytics") loadAnalytics().catch(handleApiError);
    if (view === "providers") { loadProviderHealth().catch(handleApiError); loadStreamHealth().catch(handleApiError); loadTrialMonitor().catch(handleApiError); loadDlq().catch(handleApiError); }
    if (view === "settings") { loadQrisSettings().catch(handleApiError); loadSiteSettings().catch(handleApiError); loadTelegramSettings().catch(handleApiError); refreshPinStatus().catch(() => {}); }
    window.scrollTo({ top: 0, behavior: "smooth" });
    document.body.classList.remove("menu-open");
  }

  async function loadDashboard() {
    // Audit 2026-10-25, K28: catch PER PANGGILAN, bukan Promise.all
    // tanpa catch. Satu endpoint yang gagal (non-auth) tidak boleh
    // menjatuhkan admin ke layar login: data yang berhasil tetap
    // dirender, kegagalan ditandai toast + catatan di view. Hanya
    // kegagalan sesi 401 yang dilempar ke initialize — di sana
    // showLoginOnly memang benar. 403 (BESAR-4, 2026-10-27) BUKAN
    // kegagalan sesi: ia jatuh ke jalur muat-sebagian di bawah,
    // shell tetap tampil, sesi tidak dibuang.
    const settled = await Promise.all([
      api("/v1/admin/overview"),
      api("/v1/admin/products"),
      api("/v1/admin/provider-endpoints"),
      api("/v1/admin/banks"),
      api("/v1/admin/packages"),
      api("/v1/admin/rate-limits"),
      api("/v1/admin/api-keys"),
      api("/v1/admin/provider-guard").catch(() => null),
      api("/v1/admin/rate-limit-default").catch(() => null),
    ].map((promise) => promise.then(
      (value) => ({ ok: true, value }),
      (error) => ({ ok: false, error }),
    )));
    const authFailure = settled.find((entry) => !entry.ok && entry.error instanceof ApiError && entry.error.status === 401);
    if (authFailure) throw authFailure.error;
    const values = settled.map((entry) => (entry.ok ? entry.value : undefined));
    if (values[0] !== undefined) state.overview = values[0];
    if (values[1] !== undefined) state.products = values[1];
    if (values[2] !== undefined) state.providers = values[2];
    if (values[3] !== undefined) state.banks = values[3];
    if (values[4] !== undefined) state.packages = values[4];
    if (values[5] !== undefined) state.rateLimits = values[5];
    if (values[6] !== undefined) state.apiKeys = values[6];
    if (values[7] !== undefined) state.guard = values[7];
    if (values[8] !== undefined) state.rateDefault = values[8];
    state.dashboardLoadError = settled.some((entry) => !entry.ok);
    if (state.dashboardLoadError) {
      showToast("Sebagian data dashboard gagal dimuat — menampilkan data yang berhasil. Coba muat ulang.", "error");
    }
    const note = $("#dashboard-load-error");
    if (note) note.hidden = !state.dashboardLoadError;
    renderAll();
  }

  async function refreshOverview() {
    const overview = await api("/v1/admin/overview");
    state.overview = overview;
    renderOverview();
    renderActivity();
  }

  function renderAll() {
    renderOverview();
    renderProviders();
    renderTesterBanks();
    renderTesterWallets();
    renderProducts();
    renderPackages();
    renderRateLimits();
    renderApiKeys();
    renderActivity();
    renderSettings();
  }

  function renderOverview() {
    const overview = state.overview;
    if (!overview) return;
    const metrics = overview.metrics;
    const metricConfig = [
      ["total_requests_today", metrics.total_requests_today, formatNumber, metrics.request_change_percent, "dari kemarin"],
      ["success_rate", metrics.success_rate, (value) => `${Number(value).toLocaleString("id-ID", { maximumFractionDigits: 1 })}%`, metrics.success_rate_change_percent, "dibanding kemarin"],
      ["average_latency_ms", metrics.average_latency_ms, (value) => `${formatNumber(value)} ms`, metrics.average_latency_change_percent, "lebih cepat"],
      ["estimated_revenue", metrics.estimated_revenue, formatRupiah, metrics.revenue_change_percent, "dari kemarin"],
    ];

    metricConfig.forEach(([key, value, formatter, change, suffix]) => {
      const target = $(`[data-metric="${key}"]`);
      const changeTarget = $(`[data-change="${key === "total_requests_today" ? "request_change_percent" : key === "success_rate" ? "success_rate_change_percent" : key === "average_latency_ms" ? "average_latency_change_percent" : "revenue_change_percent"}"]`);
      if (target) target.textContent = formatter(value);
      if (changeTarget) {
        const isPositive = Number(change) >= 0 || key === "average_latency_ms";
        changeTarget.className = isPositive ? "positive" : "negative";
        changeTarget.textContent = `${formatPercentage(Math.abs(change))} ${suffix}`;
      }
    });

    $("#mode-banner").hidden = !overview.demo_mode;
    renderTrafficChart(overview.traffic || []);
    renderServices(overview.services || []);
    renderActivityList("#recent-activity-list", (overview.recent_activities || []).slice(0, 5), false);
  }

  function renderTrafficChart(points) {
    const container = $("#traffic-chart");
    if (!points.length) {
      container.innerHTML = `<div class="empty-state">Belum ada data trafik untuk ditampilkan.</div>`;
      return;
    }

    const width = 720;
    const height = 230;
    const padding = { top: 18, right: 20, bottom: 31, left: 45 };
    const innerWidth = width - padding.left - padding.right;
    const innerHeight = height - padding.top - padding.bottom;
    const max = Math.max(...points.map((point) => Number(point.requests)), 1);
    const grid = 4;
    const toPoint = (value, index) => {
      const x = padding.left + (innerWidth / Math.max(points.length - 1, 1)) * index;
      const y = padding.top + innerHeight - (Number(value) / max) * innerHeight;
      return [x, y];
    };
    const requestPoints = points.map((point, index) => toPoint(point.requests, index));
    const successPoints = points.map((point, index) => toPoint(point.successful, index));
    const path = (values) => values.map(([x, y], index) => `${index ? "L" : "M"}${x.toFixed(2)} ${y.toFixed(2)}`).join(" ");
    const areaPath = `${path(requestPoints)} L ${requestPoints.at(-1)[0].toFixed(2)} ${(padding.top + innerHeight).toFixed(2)} L ${requestPoints[0][0].toFixed(2)} ${(padding.top + innerHeight).toFixed(2)} Z`;
    const gridLines = Array.from({ length: grid + 1 }, (_, index) => {
      const y = padding.top + (innerHeight / grid) * index;
      const value = Math.round(max - (max / grid) * index);
      return `<line class="chart-grid-line" x1="${padding.left}" x2="${width - padding.right}" y1="${y}" y2="${y}"/><text class="chart-label" x="0" y="${y + 3}">${formatShort(value)}</text>`;
    }).join("");
    const labels = points.map((point, index) => {
      const [x] = requestPoints[index];
      return `<text class="chart-label" text-anchor="middle" x="${x}" y="${height - 7}">${escapeHtml(point.label)}</text>`;
    }).join("");
    const dots = requestPoints.map(([x, y]) => `<circle class="chart-dot" cx="${x}" cy="${y}" r="3.5"/>`).join("");

    container.innerHTML = `<svg class="traffic-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Grafik volume request API"><defs><linearGradient id="trafficGradient" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#42aef5" stop-opacity=".36"/><stop offset="100%" stop-color="#42aef5" stop-opacity="0"/></linearGradient></defs>${gridLines}<path class="chart-area" d="${areaPath}"/><path class="chart-line-total" d="${path(requestPoints)}"/><path class="chart-line-success" d="${path(successPoints)}"/>${dots}${labels}</svg>`;
  }

  function formatShort(value) {
    if (value >= 1000) return `${(value / 1000).toFixed(value >= 10000 ? 0 : 1)}k`;
    return String(value);
  }

  function renderServices(services) {
    const container = $("#service-list");
    if (!services.length) {
      container.innerHTML = `<div class="empty-state">Status layanan belum tersedia.</div>`;
      return;
    }
    container.innerHTML = services.map((service) => `
      <div class="service-row">
        <span class="service-status-dot ${escapeHtml(service.status)}"></span>
        <div class="service-info"><strong>${escapeHtml(service.label)}</strong><small>${escapeHtml(service.detail)}</small></div>
        <span class="service-latency">${service.latency_ms ? `${formatNumber(service.latency_ms)} ms` : "—"}</span>
      </div>`).join("");
  }

  function renderActivityList(selector, activities, extended) {
    const container = $(selector);
    if (!activities.length) {
      container.innerHTML = `<div class="empty-state">Belum ada aktivitas yang terekam.</div>`;
      return;
    }
    container.innerHTML = activities.map((activity) => {
      const status = String(activity.status || "info").toLowerCase();
      const symbol = status === "valid" ? "✓" : status === "pending" ? "◷" : activity.product ? "⌁" : "✦";
      return `<div class="activity-row">
        <span class="activity-symbol ${escapeHtml(status)}">${symbol}</span>
        <div class="activity-copy"><strong>${escapeHtml(activity.title)}</strong><span>${escapeHtml(activity.detail)}</span></div>
        <time class="activity-time" datetime="${escapeHtml(activity.occurred_at)}" title="${formatDate(activity.occurred_at)}">${extended ? formatDate(activity.occurred_at) : relativeTime(activity.occurred_at)}</time>
      </div>`;
    }).join("");
  }

  function modeLabel(mode) {
    return mode === "tukangcek" ? "Tukangcek" : mode === "cutiezy" ? "Cutiezy" : "Generic";
  }

  function cutiezyProviderMapping(product) {
    return {
      status_path: "success",
      valid_values: ["true"],
      invalid_values: [],
      not_found_values: ["false"],
      pending_values: [],
      message_path: null,
      account_name_path: product === "whatsapp" ? null : product === "ewallet" ? "data.nickname" : "data.accountname",
      provider_path: product === "ewallet" ? "data.brand" : null,
      registered_path: null,
      reference_path: null,
    };
  }

  function presetMapping(product, mode) {
    if (mode === "tukangcek") return tukangcekProviderMapping(product);
    if (mode === "cutiezy") return cutiezyProviderMapping(product);
    return defaultProviderMapping(product);
  }

  function mappingSummary(endpoint) {
    const mapping = endpoint.response_mapping || {};
    if (endpoint.request_mode === "cutiezy") {
      return `Status: success · Nama: ${mapping.account_name_path || "data.accountname"}`;
    }
    if (endpoint.product === "bank_account") {
      return `Status: ${mapping.status_path || "—"} · Nama: ${mapping.account_name_path || "tidak dipetakan"}`;
    }
    if (endpoint.product === "ewallet") {
      return `Status terdaftar: ${mapping.registered_path || mapping.status_path || "—"} · Nama: ${mapping.account_name_path || "tidak dipetakan"}`;
    }
    return `Status: ${mapping.status_path || "—"} · Terdaftar: ${mapping.registered_path || "dari status"}`;
  }

  function defaultProviderMapping(product) {
    return {
      status_path: "status",
      valid_values: ["valid", "success", "registered"],
      invalid_values: ["invalid", "unregistered"],
      not_found_values: ["not_found", "not found"],
      pending_values: ["pending", "processing"],
      message_path: "message",
      account_name_path: product === "whatsapp" ? null : "result.account_name",
      provider_path: "result.provider",
      registered_path: product === "bank_account" ? null : "result.registered",
      reference_path: "result.reference",
    };
  }

  function tukangcekProviderMapping(product) {
    if (product === "whatsapp") {
      return {
        status_path: "registered",
        valid_values: ["true"],
        invalid_values: [],
        not_found_values: ["false"],
        pending_values: [],
        message_path: null,
        account_name_path: null,
        provider_path: null,
        registered_path: "registered",
        reference_path: null,
      };
    }
    return {
      status_path: "found",
      valid_values: ["true"],
      invalid_values: [],
      not_found_values: ["false"],
      pending_values: [],
      message_path: null,
      account_name_path: "name",
      provider_path: null,
      registered_path: product === "ewallet" ? "found" : null,
      reference_path: null,
    };
  }

  function renderTesterBanks() {
    const select = $("#tester-bank-code");
    if (!select) return;
    select.innerHTML = state.banks.map((bank) => `<option value="${escapeHtml(bank.code_bank)}" ${bank.tukangcek_code ? "" : "disabled"}>${escapeHtml(bank.code_bank)} · ${escapeHtml(bank.name_bank)}${bank.tukangcek_code ? "" : " · mapping belum tersedia"}</option>`).join("");
    if (state.banks.some((bank) => bank.code_bank === "002" && bank.tukangcek_code)) select.value = "002";
  }

  function renderTesterWallets() {
    const wallets = [
      ["dana", "DANA"], ["astrapay", "AstraPay"], ["gopay", "GoPay"],
      ["gopay_driver", "GoPay Driver"], ["isaku", "i.saku"], ["kaspro", "KasPro"],
      ["linkaja", "LinkAja"], ["ovo", "OVO"], ["shopeepay", "ShopeePay"],
    ];
    const select = $("#tester-ewallet-provider");
    select.innerHTML = wallets.map(([slug, name]) => `<option value="${slug}">${name}</option>`).join("");
  }

  function updateTesterFields() {
    const product = $("#tester-product").value;
    $$(".tester-bank-field").forEach((field) => { field.hidden = product !== "bank_account"; });
    $$(".tester-ewallet-field").forEach((field) => { field.hidden = product !== "ewallet"; });
    const endpointSelect = $("#tester-endpoint");
    if (endpointSelect) {
      const servers = state.providers.filter((endpoint) => endpoint.product === product && endpoint.active);
      endpointSelect.innerHTML = `<option value="">Semua server aktif (balapan)</option>` + servers.map((endpoint) => `<option value="${endpoint.id}">${escapeHtml(endpoint.name)}</option>`).join("");
    }
    const label = product === "bank_account" ? "Nomor rekening" : product === "ewallet" ? "Nomor e-wallet" : product === "pln" ? "ID pelanggan PLN" : "Nomor WhatsApp";
    $("#tester-target-label").textContent = label;
    $("#tester-target").placeholder = product === "whatsapp" ? "081234567890" : "1234567890";
  }

  function selectTesterTab(name, focus = false) {
    for (const tab of $$("[data-tester-tab]")) {
      const active = tab.dataset.testerTab === name;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
      $(`#tester-panel-${tab.dataset.testerTab}`).hidden = !active;
      if (active && focus) tab.focus();
    }
  }

  function testerRow(label, value) {
    return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`;
  }

  function renderTesterRaw(raw) {
    const status = $("#tester-raw-status");
    const body = $("#tester-raw");
    if (!raw || typeof raw.http_status !== "number") {
      status.textContent = "Tidak ada respons HTTP dari provider untuk permintaan ini.";
      body.textContent = "Respons asli tidak tersedia.";
      return;
    }
    status.textContent = `HTTP ${raw.http_status}${raw.server_name ? ` · Server: ${raw.server_name}` : ""} · ${raw.encoding === "base64" ? "Base64 (respons biner)" : "UTF-8"}${raw.truncated ? " · Dipotong pada 64 KiB" : ""}`;
    body.textContent = String(raw.body ?? "");
  }

  function renderTesterResult(result) {
    const container = $("#tester-result");
    const safeResult = result.result || {};
    container.className = "tester-result";
    container.innerHTML = `<div class="tester-result-status">${statusBadge(result.status)}</div><div class="latency-grid"><div><span>Provider</span><strong>${formatNumber(result.provider_latency_ms)} ms</strong></div><div><span>Proses Rajacek</span><strong>${formatNumber(result.rajacek_processing_ms)} ms</strong></div><div><span>Total</span><strong>${formatNumber(result.total_latency_ms)} ms</strong></div></div><dl>${testerRow("Layanan", productLabel(result.product))}${testerRow("Provider", result.provider)}${testerRow("Percobaan", result.attempts > 1 ? `Ke-${result.attempts} (setelah ${result.attempts - 1}× coba ulang)` : "Pertama (tanpa coba ulang)")}${testerRow("Valid", result.valid ? "Ya" : "Tidak")}${testerRow("Pesan", result.message)}${safeResult.account_name ? testerRow(result.product === "bank_account" ? "Nama rekening" : "Nama akun", safeResult.account_name) : ""}${safeResult.tarif ? testerRow("Tarif", safeResult.tarif) : ""}${safeResult.daya ? testerRow("Daya", safeResult.daya) : ""}${safeResult.provider ? testerRow("Provider hasil", safeResult.provider) : ""}${typeof safeResult.registered === "boolean" ? testerRow("Terdaftar", safeResult.registered ? "Ya" : "Tidak") : ""}${safeResult.reference ? testerRow("Referensi", safeResult.reference) : ""}</dl>`;
    $("#tester-json").textContent = JSON.stringify(result, null, 2);
    renderTesterRaw(result.upstream_response);
  }

  function renderTesterError(error) {
    const payload = error instanceof ApiError && error.payload && typeof error.payload === "object"
      ? error.payload
      : { code: "network_error", message: error instanceof ApiError ? error.message : "Terjadi kesalahan tak terduga." };
    const status = error instanceof ApiError && error.status ? `HTTP ${error.status}` : "Koneksi gagal";
    const container = $("#tester-result");
    container.className = "tester-result tester-result-error";
    container.innerHTML = `<div class="tester-result-status"><span class="status-badge inactive">${escapeHtml(status)}</span></div><dl>${testerRow("Kode", payload.code || "request_failed")}${testerRow("Pesan", payload.message || "Permintaan gagal.")}${payload.request_id ? testerRow("Request ID", payload.request_id) : ""}</dl>`;
    $("#tester-json").textContent = JSON.stringify(payload, null, 2);
    renderTesterRaw(payload.details?.upstream_response);
  }

  async function submitProviderTester(event) {
    event.preventDefault();
    const product = $("#tester-product").value;
    const payload = {
      product,
      target: $("#tester-target").value.trim(),
      bank_code: product === "bank_account" ? $("#tester-bank-code").value : null,
      ewallet_provider: product === "ewallet" ? $("#tester-ewallet-provider").value : null,
      endpoint_id: $("#tester-endpoint") && $("#tester-endpoint").value ? $("#tester-endpoint").value : null,
    };
    const button = event.submitter;
    if (button) button.disabled = true;
    $("#tester-result").className = "tester-result empty-state";
    $("#tester-result").textContent = "Menunggu respons provider...";
    $("#tester-json").textContent = "Menunggu respons provider...";
    $("#tester-raw-status").textContent = "Menunggu respons provider...";
    $("#tester-raw").textContent = "Menunggu respons provider...";
    try {
      const result = await api("/v1/admin/provider-tester", { method: "POST", body: payload });
      renderTesterResult(result);
      showToast("Respons tester diterima.", "success");
    } catch (error) {
      renderTesterError(error);
      handleApiError(error);
    } finally {
      if (button) button.disabled = false;
    }
  }

  // Daftar server ringkas: satu baris per server, detail teknis dilipat.
  // Semua data-action dipertahankan agar delegasi klik lama tetap jalan.
  function endpointHost(baseUrl) {
    if (!baseUrl) return "—";
    try {
      return new URL(baseUrl).host;
    } catch (_) {
      return baseUrl;
    }
  }

  function renderProviders() {
    const container = $("#provider-grid");
    const summary = $("#provider-contract-summary");
    const activeCount = state.providers.filter((endpoint) => endpoint.active).length;
    if (summary) {
      const chips = ["bank_account", "ewallet", "whatsapp", "pln"].map((product) => {
        const servers = state.providers.filter((endpoint) => endpoint.product === product);
        const active = servers.filter((endpoint) => endpoint.active);
        const names = active.map((endpoint) => escapeHtml(endpoint.name)).join(" + ");
        return `<span class="ep-sum-chip"><b>${productLabel(product)}</b> ${active.length ? names + (active.length > 1 ? " · balapan" : "") : "tidak ada server aktif"}</span>`;
      }).join("");
      summary.classList.remove("is-tukangcek");
      summary.innerHTML = `<span class="section-kicker">Server aktif</span><h2>${activeCount} dari ${state.providers.length} server aktif</h2><div class="ep-sum">${chips}</div>`;
    }
    const products = ["bank_account", "ewallet", "whatsapp", "pln"];
    container.innerHTML = products.map((product) => {
      const servers = state.providers.filter((endpoint) => endpoint.product === product);
      const activeServers = servers.filter((endpoint) => endpoint.active);
      const rows = servers.length ? servers.map((endpoint) => `<article class="ep-row">
      <div class="ep-main">
        <span class="ep-dot ${endpoint.active ? "on" : ""}" aria-hidden="true"></span>
        <div class="ep-id">
          <strong class="ep-name">${escapeHtml(endpoint.name)}</strong>
          <span class="ep-host" title="${escapeHtml(endpoint.base_url || "")}">${escapeHtml(endpointHost(endpoint.base_url))}</span>
        </div>
        <span class="ep-chip">${modeLabel(endpoint.request_mode)}</span>
        <span class="ep-meta">${formatNumber(endpoint.timeout_ms)} ms</span>
        <span class="ep-cred">${endpoint.api_key_configured ? "•••• tersimpan" : "Kunci belum diisi"}</span>
        ${endpoint.force_on ? `<span class="ep-chip" title="Paksa ON: tetap di-admit meski circuit breaker terbuka">DIPAKSA ON</span>` : ""}
      </div>
      <div class="ep-actions">
        <label class="ep-switch" title="${endpoint.active ? "Matikan server" : "Aktifkan server"}"><input type="checkbox" data-action="toggle-provider" data-id="${endpoint.id}" ${endpoint.active ? "checked" : ""} /><span aria-hidden="true"></span></label>
        <label class="ep-switch" title="Paksa ON: tetap di-admit meski circuit breaker terbuka"><input type="checkbox" data-action="toggle-provider-force" data-id="${endpoint.id}" ${endpoint.force_on ? "checked" : ""} /><span aria-hidden="true"></span></label>
        <button class="table-action" type="button" data-action="test-provider" data-id="${endpoint.id}">Tes</button>
        <button class="table-action" type="button" data-action="edit-provider" data-id="${endpoint.id}">Kelola</button>
        <button class="table-action" type="button" data-action="duplicate-provider" data-id="${endpoint.id}">Duplikat</button>
        <button class="table-action danger" type="button" data-action="delete-provider" data-id="${endpoint.id}">Hapus</button>
        <button class="ep-detail-btn" type="button" data-action="toggle-provider-detail" data-id="${endpoint.id}" aria-expanded="false">Detail ▾</button>
      </div>
      <div class="ep-detail" hidden>
        <div><span>URL lengkap</span><code>${escapeHtml(endpoint.base_url || "—")}</code></div>
        <div><span>Kontrak request</span><strong>${modeLabel(endpoint.request_mode)}${endpoint.request_mode === "generic" ? ` · ${(endpoint.http_method || "POST").toUpperCase()}` : ""} · ${endpoint.auth_header ? escapeHtml(endpoint.auth_header) : "tanpa header auth"}</strong></div>
        <div><span>Mapping JSON</span><span>${escapeHtml(mappingSummary(endpoint))}</span></div>
        ${endpoint.product === "ewallet" ? `<div><span>Mapping kode</span><span>${escapeHtml(serviceMappingSummary(endpoint))}</span></div>` : endpoint.product === "bank_account" ? `<div><span>Mapping kode</span><span>${escapeHtml(bankMappingSummary(endpoint))}</span></div>` : ""}
        <div><span>Terakhir diubah</span><span>${formatDate(endpoint.updated_at)}</span></div>
      </div>
    </article>`).join("") : `<div class="ep-empty">Belum ada server untuk layanan ini.</div>`;
      return `<div class="provider-group"><div class="provider-group-head"><div><h3>${productLabel(product)}</h3><span class="ep-group-meta">${servers.length} server · ${activeServers.length} aktif</span></div><button class="button button-secondary" type="button" data-action="add-provider" data-id="${product}">+ Tambah Server</button></div>${rows}</div>`;
    }).join("");
    if ($("#tester-endpoint")) updateTesterFields();
  }

  function renderProducts() {
    const container = $("#product-grid");
    if (!state.products.length) {
      container.innerHTML = `<div class="empty-state">Produk belum tersedia.</div>`;
      return;
    }
    container.innerHTML = state.products.map((product) => {
      const avatar = product.code.includes("bank") ? "⌁" : product.code.includes("wallet") ? "◫" : "◌";
      const avatarClass = product.code.includes("wallet") ? "wallet" : product.code.includes("whatsapp") ? "chat" : "";
      return `<article class="product-card">
        <div class="product-card-top"><span class="product-avatar ${avatarClass}">${avatar}</span>${statusBadge(product.active ? "active" : "inactive")}</div>
        <h2>${escapeHtml(product.name)}</h2><p>${escapeHtml(product.description)}</p>
        <div class="product-details"><div class="product-detail"><span>Rute provider</span><code>${escapeHtml(product.provider_route)}</code></div><div class="product-detail"><span>Terakhir diubah</span><span>${formatDate(product.updated_at)}</span></div></div>
        <div class="price-row"><button class="card-action" type="button" data-action="edit-product" data-id="${product.id}">Kelola →</button></div>
      </article>`;
    }).join("");
  }

  function renderPackages() {
    const container = $("#package-grid");
    if (!state.packages.length) {
      container.innerHTML = `<div class="empty-state">Belum ada paket. Buat paket pertama Anda.</div>`;
      return;
    }
    container.innerHTML = state.packages.map((item) => {
      const productItems = item.products.map(productLabel).join(", ");
      const promoOn = item.promo_percent > 0 && item.promo_ends_at && new Date(item.promo_ends_at) > Date.now();
      const effPrice = promoOn ? Math.round(item.price_idr * (100 - item.promo_percent) / 100) : item.price_idr;
      return `<article class="package-card ${item.highlighted ? "is-highlighted" : ""}">
        <div class="package-card-top"><span class="status-badge ${item.active ? "active" : "inactive"}">${item.active ? "Aktif" : "Nonaktif"}</span>${item.highlighted ? '<span class="package-highlight">Pilihan utama</span>' : ""}</div>
        <h2>${escapeHtml(item.name)}</h2><p>${escapeHtml(item.description)}</p>
        ${promoOn ? `<div class="package-promo"><span class="promo-badge">PROMO −${item.promo_percent}%</span><span class="package-countdown" data-countdown-to="${escapeHtml(item.promo_ends_at)}"></span></div>` : ""}
        <div class="package-price">${formatRupiah(effPrice)} <small>/ paket</small></div>
        ${promoOn ? `<div class="package-old">${formatRupiah(item.price_idr)}</div>` : ""}
        <ul class="package-list"><li>${formatNumber(item.included_hits)} hit termasuk</li><li>${formatNumber(item.rate_limit_per_minute)} request per menit</li><li>${escapeHtml(productItems)}</li></ul>
        <div class="package-actions"><button class="button button-secondary" type="button" data-action="edit-package" data-id="${item.id}">Edit</button><button class="button button-primary" type="button" data-action="duplicate-package" data-id="${item.id}">Duplikasi</button><button class="button button-secondary" type="button" data-action="delete-package" data-id="${item.id}">Hapus</button></div>
      </article>`;
    }).join("");
  }

  /* Hitung mundur promo di kartu paket: tiap detik; promo yang habis
     memuat ulang daftar dari server sekali (jeda 60 dtk). */
  function fmtCountdown(ms) {
    if (ms <= 0) return "Promo berakhir";
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60;
    const p = (n) => String(n).padStart(2, "0");
    return (d > 0 ? d + " hari " : "") + p(h) + ":" + p(m) + ":" + p(sec);
  }
  let promoRefreshAt = 0;
  setInterval(() => {
    let expired = false;
    $$("[data-countdown-to]").forEach((el) => {
      const ms = new Date(el.dataset.countdownTo) - Date.now();
      el.textContent = ms > 0 ? "Berakhir dalam " + fmtCountdown(ms) : "Promo berakhir";
      if (ms <= 0) expired = true;
    });
    if (expired && Date.now() - promoRefreshAt > 60000) {
      promoRefreshAt = Date.now();
      api("/v1/admin/packages").then((pkgs) => { state.packages = pkgs; renderPackages(); }).catch(() => {});
    }
  }, 1000);

  function renderRateDefault() {
    const input = $("#rate-default-input");
    if (!input || !state.rateDefault) return;
    if (document.activeElement !== input) input.value = state.rateDefault.default_per_minute;
    $("#rate-default-note").textContent = `Berlaku sekarang: ${formatNumber(state.rateDefault.default_per_minute)}/menit per kunci · IP ${formatNumber(state.rateDefault.ip_limit_per_minute)}/menit · global ${formatNumber(state.rateDefault.global_limit_per_minute)}/menit.`;
  }

  async function submitRateDefault(event) {
    event.preventDefault();
    try {
      const saved = await api("/v1/admin/rate-limit-default", {
        method: "PUT",
        body: { default_per_minute: Number($("#rate-default-input").value) },
      });
      state.rateDefault = saved;
      renderRateDefault();
      showToast(saved.persisted
        ? "Rate limit bawaan diperbarui, tersimpan di database, dan langsung aktif."
        : "Rate limit bawaan diperbarui dan langsung aktif (hanya memori proses — database tidak terhubung).", "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  function renderRateLimits() {
    const table = $("#rate-limit-table");
    $("#rate-limit-count").textContent = `${state.rateLimits.length} kebijakan`;
    if (!state.rateLimits.length) {
      table.innerHTML = `<tr><td colspan="8"><div class="empty-state">Belum ada kebijakan rate limit.</div></td></tr>`;
      return;
    }
    const scopeLabels = { global: "Global", api_key: "Kunci API", ip: "IP", package: "Paket", endpoint: "Endpoint" };
    table.innerHTML = state.rateLimits.map((policy) => `<tr>
      <td data-label="Nama kebijakan"><span class="table-title">${escapeHtml(policy.name)}</span><span class="table-subtitle">Diperbarui ${relativeTime(policy.updated_at)}</span></td>
      <td data-label="Scope"><span class="scope-badge">${escapeHtml(scopeLabels[policy.scope] || policy.scope)}</span></td><td data-label="Target">${escapeHtml(policy.target)}</td>
      <td data-label="Limit">${formatNumber(policy.requests_per_minute)} RPM</td><td data-label="Burst">${formatNumber(policy.burst)}</td><td data-label="Konkurensi">${formatNumber(policy.concurrency_limit)}</td>
      <td data-label="Status">${statusBadge(policy.active ? "active" : "inactive")}</td>
      <td data-label="Aksi"><span class="row-actions"><button class="table-action" data-action="edit-rate-limit" data-id="${policy.id}" type="button">Edit</button><button class="table-action danger" data-action="delete-rate-limit" data-id="${policy.id}" type="button">Hapus</button></span></td>
    </tr>`).join("");
  }

  function renderApiKeys() {
    const table = $("#api-key-table");
    $("#api-key-count").textContent = `${state.apiKeys.length} kunci`;
    if (!state.apiKeys.length) {
      table.innerHTML = `<tr><td colspan="8"><div class="empty-state">Belum ada kunci API.</div></td></tr>`;
      return;
    }
    // K32: kolom Pemilik — email member bila kunci milik member,
    // "Member" bila member_id ada tapi email tak ter-resolve (tanpa
    // database), "standalone" bila bukan kunci member.
    table.innerHTML = state.apiKeys.map((key) => {
      const owner = key.owner_email || (key.member_id ? "Member" : "standalone");
      // Billing 2026-10-25: jatah gratis hasil tidak-valid hari ini (WIB).
      const freeUsed = typeof key.invalid_free_used_today === "number" ? key.invalid_free_used_today : 0;
      return `<tr>
      <td data-label="Nama"><span class="table-title">${escapeHtml(key.name)}</span><span class="table-subtitle">Dibuat ${formatDate(key.created_at)}</span><span class="table-subtitle">Tidak-valid gratis hari ini: ${freeUsed}/100</span></td>
      <td data-label="Prefix"><code>${escapeHtml(key.prefix)}_••••••••</code></td>
      <td data-label="Scope"><span class="scope-list">${key.scopes.map((scope) => `<span class="scope-badge">${escapeHtml(scope)}</span>`).join("")}</span></td>
      <td data-label="Pemilik">${escapeHtml(owner)}</td>
      <td data-label="Rate limit">${formatNumber(key.rate_limit_per_minute)} RPM</td><td data-label="Terakhir dipakai">${formatDate(key.last_used_at)}</td><td data-label="Status">${statusBadge(key.status)}</td>
      <td data-label="Aksi">${key.status === "active" ? `<button class="table-action danger" data-action="revoke-api-key" data-id="${key.id}" type="button">Cabut</button>` : "—"}</td>
    </tr>`;
    }).join("");
  }

  function renderActivity() {
    renderActivityList("#full-activity-list", state.overview?.recent_activities || [], true);
  }

  // ---- Aktivitas admin (jejak audit persisten, B12) ----
  // Feed INI berbeda dari overview.recent_activities (riwayat
  // validasi): feed ini adalah aksi admin dari /v1/admin/activity
  // (grant, revoke, paket, settings, login) yang bertahan restart.
  async function loadAdminActivity() {
    const page = state.adminActivity;
    const params = new URLSearchParams({
      limit: String(page.limit),
      offset: String(page.offset),
    });
    if (page.action) params.set("action", page.action);
    if (page.actor) params.set("actor", page.actor);
    if (page.from) params.set("from", page.from);
    if (page.to) params.set("to", page.to);
    const data = await api(`/v1/admin/activity?${params.toString()}`);
    state.adminActivity = { ...page, items: data.items, total: data.total, loaded: true };
    renderAdminActivity();
  }

  function renderAdminActivity() {
    const page = state.adminActivity;
    const container = $("#admin-activity-list");
    if (!container) return;
    if (!page.items.length) {
      container.innerHTML = `<div class="empty-state">Belum ada aktivitas admin yang terekam.</div>`;
    } else {
      container.innerHTML = page.items.map((entry) => `<div class="activity-row">
        <span class="activity-symbol">✦</span>
        <div class="activity-copy"><strong>${escapeHtml(entry.action)}</strong><span>${escapeHtml(entry.detail)}</span><span class="tester-audit-note">oleh ${escapeHtml(entry.actor || "—")}</span></div>
        <time class="activity-time" datetime="${escapeHtml(entry.occurred_at)}" title="${formatDate(entry.occurred_at)}">${formatDate(entry.occurred_at)}</time>
      </div>`).join("");
    }
    const from = page.total === 0 ? 0 : page.offset + 1;
    const to = Math.min(page.offset + page.limit, page.total);
    const info = $("#admin-activity-page-info");
    if (info) info.textContent = `Menampilkan ${formatNumber(from)}–${formatNumber(to)} dari ${formatNumber(page.total)} aktivitas`;
    const prev = $("#admin-activity-prev");
    const next = $("#admin-activity-next");
    if (prev) prev.disabled = page.offset <= 0;
    if (next) next.disabled = page.offset + page.limit >= page.total;
  }

  async function loadAdminAccounts() {
    const accounts = await api("/v1/admin/admins");
    state.adminAccounts = accounts;
    renderAdminAccounts();
  }

  function renderAdminAccounts() {
    const tbody = $("#admins-table");
    if (!tbody) return;
    if (!state.adminAccounts.length) {
      tbody.innerHTML = "";
      $("#admins-empty").hidden = false;
      return;
    }
    $("#admins-empty").hidden = true;
    tbody.innerHTML = state.adminAccounts.map((account) => {
      const roleLabels = { viewer: "Viewer", support: "Support", manager: "Manager", owner: "Owner" };
      const roleOptions = ["viewer", "support", "manager", "owner"].map((role) => `<option value="${role}" ${account.role === role ? "selected" : ""}>${roleLabels[role]}</option>`).join("");
      return `<tr><td data-label="Email">${escapeHtml(account.email)}</td><td data-label="Peran"><select class="admin-role-select" data-id="${account.id}">${roleOptions}</select></td><td data-label="Status">${statusBadge(account.active ? "active" : "inactive")}</td><td data-label="Dibuat">${formatDate(account.created_at)}</td><td data-label="Aksi"><button class="table-action" type="button" data-action="admin-toggle" data-id="${account.id}" data-active="${account.active ? "1" : "0"}">${account.active ? "Nonaktifkan" : "Aktifkan"}</button><button class="table-action danger" type="button" data-action="admin-delete" data-id="${account.id}">Hapus</button></td></tr>`;
    }).join("");
    $$(".admin-role-select", tbody).forEach((select) => {
      select.addEventListener("change", async () => {
        const id = select.dataset.id;
        if (!window.confirm(`Ubah peran admin ini menjadi ${select.value}?`)) { loadAdminAccounts().catch(handleApiError); return; }
        try {
          await api(`/v1/admin/admins/${id}`, { method: "PATCH", body: { role: select.value } });
          showToast("Peran admin diperbarui.", "success");
          await loadAdminAccounts();
        } catch (error) { handleApiError(error); loadAdminAccounts().catch(() => {}); }
      });
    });
  }

  async function toggleAdminAccount(id, nextActive) {
    const account = state.adminAccounts.find((item) => item.id === id);
    if (!window.confirm(`${nextActive ? "Aktifkan" : "Nonaktifkan"} admin ${account ? account.email : ""}?`)) return;
    try {
      await api(`/v1/admin/admins/${id}`, { method: "PATCH", body: { active: nextActive } });
      showToast(`Admin ${nextActive ? "diaktifkan" : "dinonaktifkan"}.`, "success");
      await loadAdminAccounts();
    } catch (error) { handleApiError(error); }
  }

  async function deleteAdminAccount(id) {
    const account = state.adminAccounts.find((item) => item.id === id);
    if (!window.confirm(`Hapus admin ${account ? account.email : ""}? Tindakan ini tidak dapat dibatalkan.`)) return;
    try {
      await api(`/v1/admin/admins/${id}`, { method: "DELETE" });
      showToast("Admin dihapus.", "success");
      await loadAdminAccounts();
    } catch (error) { handleApiError(error); }
  }

  async function loadHistory() {
    const params = new URLSearchParams({
      limit: String(state.history.limit),
      offset: String(state.history.offset),
    });
    const product = $("#history-product").value;
    const outcome = $("#history-outcome").value;
    const prefix = $("#history-prefix").value.trim();
    const q = $("#history-q")?.value.trim();
    const from = $("#history-from")?.value;
    const to = $("#history-to")?.value;
    if (product) params.set("product", product);
    if (outcome) params.set("outcome", outcome);
    if (prefix) params.set("api_key_prefix", prefix);
    if (q) params.set("q", q);
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    const data = await api(`/v1/admin/validation-history?${params.toString()}`);
    state.history = { ...state.history, items: data.items, total: data.total, source: data.source, stats: data.stats, loaded: true };
    renderHistory();
  }

  function latencyCell(item) {
    const provider = formatNumber(item.provider_latency_ms);
    if (item.total_latency_ms == null) {
      return `<div class="latency-stack"><span>${provider} ms</span><span class="cell-sub">provider saja (data lama)</span></div>`;
    }
    const processing = item.rajacek_processing_ms || 0;
    const gap = Math.max(0, item.total_latency_ms - item.provider_latency_ms - processing);
    const attempts = item.attempts && item.attempts > 1 ? ` \u00b7 ${item.attempts}\u00d7 percobaan` : "";
    return `<div class="latency-stack"><span><strong>${formatNumber(item.total_latency_ms)} ms</strong> total ke member</span><span class="cell-sub">provider ${provider} ms \u00b7 proses ${formatNumber(processing)} ms \u00b7 gap ${formatNumber(gap)} ms${attempts}</span></div>`;
  }

  function startHistoryPolling() {
    stopHistoryPolling();
    state.historyTimer = setInterval(() => {
      if (document.hidden || state.activeView !== "history") return;
      loadHistory().catch(() => {});
    }, 5000);
  }

  function stopHistoryPolling() {
    if (state.historyTimer) {
      clearInterval(state.historyTimer);
      state.historyTimer = null;
    }
  }

  function renderHistory() {
    const h = state.history;
    $("#history-source").textContent = h.source === "database"
      ? "Sumber: database (permanen)"
      : "Sumber: memori proses (sejak server start)";
    const liveEl = $("#history-live");
    const hstats = h.stats || { hits_last_60s: 0, hits_last_3600s: 0 };
    const avgSecondEl = $("#history-avg-second");
    if (avgSecondEl) {
      avgSecondEl.textContent = (hstats.hits_last_60s / 60).toLocaleString("id-ID", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      $("#history-avg-second-sub").textContent = `${formatNumber(hstats.hits_last_60s)} hit dalam 60 detik terakhir`;
      $("#history-avg-minute").textContent = (hstats.hits_last_3600s / 60).toLocaleString("id-ID", { minimumFractionDigits: 1, maximumFractionDigits: 1 });
      $("#history-avg-minute-sub").textContent = `${formatNumber(hstats.hits_last_3600s)} hit dalam 60 menit terakhir`;
    }
    if (liveEl) liveEl.textContent = `\u25cf Realtime \u00b7 diperbarui ${new Date().toLocaleTimeString("id-ID")}`;
    const outcomeLabel = {
      valid: "Valid", invalid: "Tidak valid", not_found: "Tidak ditemukan",
      not_kyc: "Belum KYC",
      provider_error: "Error provider", pending: "Menunggu",
      rate_limited: "Rate limit", quota_exhausted: "Kuota habis",
    };
    $("#history-table").innerHTML = h.items.length ? h.items.map((item, idx) => {
      const occurred = formatHistoryDateTime(item.occurred_at);
      const target = item.target_raw != null && item.target_raw !== "" ? item.target_raw : item.target_masked;
      const accountName = item.account_name != null && item.account_name !== "" ? item.account_name : "—";
      return `<tr>
      <td data-label="No." class="row-num">${formatNumber(h.total - h.offset - idx)}</td>
      <td data-label="Waktu" class="history-date" title="${escapeHtml(occurred.full)}">${escapeHtml(occurred.date)}${occurred.time ? `<br /><span>${escapeHtml(occurred.time)}</span>` : ""}</td>
      <td data-label="Produk">${escapeHtml(productLabel(item.product))}</td>
      <td data-label="Target">${escapeHtml(target)}</td>
      <td data-label="Nama">${escapeHtml(accountName)}</td>
      <td data-label="Hasil"><span class="status-badge ${escapeHtml(item.outcome)}">${escapeHtml(outcomeLabel[item.outcome] || item.outcome)}</span></td>
      <td data-label="Latensi">${latencyCell(item)}</td>
      <td data-label="Request ID"><button class="table-action" type="button" data-action="history-detail" data-id="${escapeHtml(String(item.request_id))}" title="Lihat detail validasi">${escapeHtml(String(item.request_id).length <= 12 ? String(item.request_id) : String(item.request_id).slice(0, 8) + "…")}</button></td>
    </tr>`;
    }).join("") : `<tr><td colspan="8">Belum ada riwayat yang cocok dengan filter.</td></tr>`;
    const from = h.total === 0 ? 0 : h.offset + 1;
    const to = Math.min(h.offset + h.limit, h.total);
    $("#history-page-info").textContent = `Menampilkan ${formatNumber(from)}–${formatNumber(to)} dari ${formatNumber(h.total)} riwayat`;
    $("#history-prev").disabled = h.offset <= 0;
    $("#history-next").disabled = h.offset + h.limit >= h.total;
  }

  function openHistoryDetail(requestId) {
    const item = state.history.items.find((entry) => String(entry.request_id) === String(requestId));
    if (!item) return;
    const occurred = formatHistoryDateTime(item.occurred_at);
    const target = item.target_raw != null && item.target_raw !== "" ? item.target_raw : item.target_masked;
    const accountName = item.account_name != null && item.account_name !== "" ? item.account_name : "—";
    const outcomeLabel = {
      valid: "Valid", invalid: "Tidak valid", not_found: "Tidak ditemukan",
      not_kyc: "Belum KYC",
      provider_error: "Error provider", pending: "Menunggu",
      rate_limited: "Rate limit", quota_exhausted: "Kuota habis",
    };
    let latencyDetail;
    if (item.total_latency_ms == null) {
      latencyDetail = `${formatNumber(item.provider_latency_ms)} ms (provider saja, data lama)`;
    } else {
      const processing = item.rajacek_processing_ms || 0;
      const gap = Math.max(0, item.total_latency_ms - item.provider_latency_ms - processing);
      const attempts = item.attempts && item.attempts > 1 ? ` · ${item.attempts}× percobaan` : "";
      latencyDetail = `Total ${formatNumber(item.total_latency_ms)} ms · provider ${formatNumber(item.provider_latency_ms)} ms · proses ${formatNumber(processing)} ms · gap ${formatNumber(gap)} ms${attempts}`;
    }
    $("#history-detail-body").innerHTML =
      testerRow("Waktu", occurred.full)
      + testerRow("Member", `${item.member_code || "—"} (${item.api_key_prefix})`)
      + testerRow("Produk", productLabel(item.product))
      + historyHintRow(item)
      + testerRow("Target", target)
      + testerRow("Nama", accountName)
      + testerRow("Hasil", outcomeLabel[item.outcome] || item.outcome)
      // Sumber data (migration 0033) hanya untuk hasil Valid, sesuai
      // perintah: Valid + nama diketahui -> nama endpoint; Valid + null
      // (baris lama pra-fitur) -> "tidak tercatat (data lama)"; hasil
      // lain -> baris disembunyikan. Yang tampil hanya NAMA endpoint,
      // tidak pernah URL/host/kredensial.
      + (item.outcome === "valid"
        ? testerRow("Sumber data", item.provider_endpoint_name ? item.provider_endpoint_name : "tidak tercatat (data lama)")
        : "")
      + testerRow("Latensi", latencyDetail)
      + testerRow("Request ID", String(item.request_id));
    openModal("history-detail-modal");
  }

  async function loadMembers() {
    // AREA 5: filter pencarian member (q/status/from/to) — tanpa
    // parameter, URL tetap /v1/admin/members seperti dulu.
    const memberParams = new URLSearchParams();
    const q = $("#members-q")?.value.trim();
    const status = $("#members-status-filter")?.value;
    const from = $("#members-from")?.value;
    const to = $("#members-to")?.value;
    if (q) memberParams.set("q", q);
    if (status) memberParams.set("status", status);
    if (from) memberParams.set("from", from);
    if (to) memberParams.set("to", to);
    const membersQuery = memberParams.toString();
    const [members, trial] = await Promise.all([
      api(membersQuery ? `/v1/admin/members?${membersQuery}` : "/v1/admin/members"),
      api("/v1/admin/trial-settings").catch(() => null),
    ]);
    state.members = members;
    state.membersLoaded = true;
    if (trial) {
      $("#trial-quota").value = trial.quota_hits;
      $("#trial-days").value = trial.valid_days;
    }
    renderMembers();
  }

  function renderMembers() {
    // Plan efektif dari server (plan_effective); fallback ke nilai
    // tersimpan bila respons lama tanpa field itu.
    const effectivePlan = (member) => member.plan_effective || member.plan_kind;
    const planLabel = { trial: "Trial", package: "Paket", manual: "Manual", umum: "Umum" };
    const visible = state.members.filter((member) => {
      if (state.membersTab === "trial") return effectivePlan(member) === "trial";
      if (state.membersTab === "umum") return effectivePlan(member) !== "trial";
      return true;
    });
    $("#members-count").textContent = `${formatNumber(visible.length)} member`;
    $("#members-empty").hidden = visible.length > 0;
    $("#members-table").innerHTML = visible.map((member) => `<tr>
      <td data-label="Member"><strong>${escapeHtml(member.name || member.email)}</strong><br /><span class="tester-audit-note">${escapeHtml(member.email)}</span><br /><code>${escapeHtml(member.key_prefix || "—")}</code></td>
      <td data-label="Kode member"><strong>${escapeHtml(member.member_code || "—")}</strong></td>
      <td data-label="Plan">${escapeHtml(planLabel[effectivePlan(member)] || effectivePlan(member))}</td>
      <td data-label="Status"><span class="status-badge ${member.status === "active" ? "valid" : "invalid"}">${member.status === "active" ? "Aktif" : "Nonaktif"}</span>${member.key_status === "revoked" ? `<br /><span class="status-badge invalid">kunci dicabut</span>` : ""}</td>
      <td data-label="Kuota">${member.quota_remaining == null ? "—" : `${formatNumber(member.quota_remaining)} / ${formatNumber(member.quota_total)}`}</td>
      <td data-label="Aktif s/d">${member.expires_at ? escapeHtml(formatDate(member.expires_at)) : "—"}</td>
      <td data-label="Rate limit">${member.rate_limit_per_minute == null ? "—" : `${formatNumber(member.rate_limit_per_minute)}/mnt`}</td>
      <td data-label="Login terakhir">${member.last_login_at ? escapeHtml(formatDate(member.last_login_at)) : "—"}</td>
      <td data-label="Aksi"><span class="row-actions"><button class="button button-secondary" type="button" data-member-detail="${escapeHtml(member.id)}">Detail</button><button class="button button-secondary" type="button" data-manage-member="${escapeHtml(member.id)}">Kelola</button></span></td>
    </tr>`).join("");
    $$("#members-table [data-manage-member]").forEach((button) => {
      button.addEventListener("click", () => openMemberManage(button.dataset.manageMember));
    });
    $$("#members-table [data-member-detail]").forEach((button) => {
      button.addEventListener("click", () => openMemberDetail(button.dataset.memberDetail));
    });
    // Paket untuk dropdown assign (dari state.packages bila sudah dimuat).
    const select = $("#member-assign-package");
    select.innerHTML = state.packages.length
      ? state.packages.map((pkg) => `<option value="${escapeHtml(pkg.id)}">${escapeHtml(pkg.name)} — ${formatNumber(pkg.included_hits)} hit · ${formatNumber(pkg.rate_limit_per_minute)}/mnt</option>`).join("")
      : `<option value="">(belum ada paket — buat dulu di view Paket)</option>`;
  }

  // AREA 5: unduh CSV export admin. api() hanya menangani JSON,
  // jadi fetch dipakai langsung: respons error tetap JSON (pesan
  // ditampilkan), respons sukses adalah blob CSV yang diunduh lewat
  // <a> sementara. Nama file diambil dari Content-Disposition bila ada.
  async function downloadAdminExport(kind, params) {
    const query = params.toString();
    const url = query ? `/v1/admin/export/${kind}?${query}` : `/v1/admin/export/${kind}`;
    let response;
    try {
      response = await fetch(url, { cache: "no-store", headers: apiHeaders() });
    } catch {
      throw new ApiError("Tidak dapat menghubungi server. Periksa koneksi Anda.", 0, null);
    }
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      throw new ApiError(payload?.message || `Export gagal (${response.status}).`, response.status, payload);
    }
    if (response.headers.get("x-export-truncated") === "true") {
      alert("Export dipotong pada 10.000 baris pertama. Persempit filter (status/rentang tanggal) untuk mengunduh sisanya.");
    }
    const blob = await response.blob();
    const disposition = response.headers.get("content-disposition") || "";
    const filenameMatch = /filename="([^"]+)"/.exec(disposition);
    const filename = filenameMatch ? filenameMatch[1] : `rajacek-export-${kind}.csv`;
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  }

  function exportOrdersParams() {
    const params = new URLSearchParams();
    const status = $("#orders-status-filter")?.value;
    const q = $("#orders-q")?.value.trim();
    const from = $("#orders-from-filter")?.value;
    const to = $("#orders-to-filter")?.value;
    if (status) params.set("status", status);
    if (q) params.set("q", q);
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    return params;
  }

  function exportMembersParams() {
    const params = new URLSearchParams();
    const q = $("#members-q")?.value.trim();
    const status = $("#members-status-filter")?.value;
    const from = $("#members-from")?.value;
    const to = $("#members-to")?.value;
    if (q) params.set("q", q);
    if (status) params.set("status", status);
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    // Export mengikuti tab yang aktif (server memfilter plan efektif).
    if (state.membersTab && state.membersTab !== "all") params.set("tab", state.membersTab);
    return params;
  }

  function exportHistoryParams() {
    const params = new URLSearchParams();
    const product = $("#history-product")?.value;
    const outcome = $("#history-outcome")?.value;
    const prefix = $("#history-prefix")?.value.trim();
    const q = $("#history-q")?.value.trim();
    const from = $("#history-from")?.value;
    const to = $("#history-to")?.value;
    if (product) params.set("product", product);
    if (outcome) params.set("status", outcome);
    if (prefix) params.set("api_key_prefix", prefix);
    if (q) params.set("q", q);
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    return params;
  }

  // ---- Order QRIS + pengaturan QRIS ----
  async function loadOrders() {
    // K27: paginasi limit/offset (default 100, sama seperti dulu).
    // Backend mengembalikan array tanpa total, jadi tombol Berikutnya
    // dinonaktifkan bila halaman tidak penuh — halaman penuh terakhir
    // yang persis kelipatan limit akan menampilkan satu halaman kosong
    // berikutnya, itu batas yang diterima dari kontrak array ini.
    const status = $("#orders-status-filter").value;
    const q = $("#orders-q")?.value.trim();
    const from = $("#orders-from-filter")?.value || "";
    const to = $("#orders-to-filter")?.value || "";
    const params = new URLSearchParams({
      limit: String(state.ordersPage.limit),
      offset: String(state.ordersPage.offset),
    });
    if (status) params.set("status", status);
    if (q) params.set("q", q);
    // AREA 3: rentang tanggal dikirim apa adanya; validasi (lengkap /
    // maks 366 hari) ada di server — error 400 tampil lewat handler.
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    state.orders = await api(`/v1/admin/orders?${params.toString()}`);
    renderOrders();
    loadRecon().catch(() => {});
    loadAlertStatus().catch(() => {});
    loadOrphanQr().catch(() => {});
  }

  // K26: daftar QR yatim (QR Cutiezy berbayar tanpa baris order) +
  // form resolve-berbukti (pilih paket + RRN dashboard). QR yatim yang
  // gagal dibatalkan dulu hanya meninggalkan log; kini admin bisa
  // meng-grant-nya dari panel bila check-status membuktikan lunas.
  async function loadOrphanQr() {
    const box = $("#orphan-qr-box");
    if (!box) return;
    try {
      const items = await api("/v1/admin/orphan-qr");
      if (!items.length) {
        box.innerHTML = "";
        return;
      }
      if (!state.packages.length) {
        try { state.packages = await api("/v1/admin/packages"); } catch (_) { /* dropdown paket diisi seadanya */ }
      }
      const pkgOptions = state.packages.length
        ? state.packages.map((pkg) => `<option value="${escapeHtml(pkg.id)}">${escapeHtml(pkg.name)} — ${formatNumber(pkg.included_hits)} hit</option>`).join("")
        : `<option value="">(paket belum dimuat)</option>`;
      box.innerHTML = `<div class="order-section"><h3 class="order-section-title">QR yatim (belum punya order)</h3>
        <p class="tester-audit-note">QR yang sudah terbit di Cutiezy tapi gagal dibatalkan saat create gagal. Bila member membayar QR ini, resolve-berbukti di bawah (cocokkan RRN + nominal lewat check-status) akan membuat order + grant — tanpa ini uangnya menggantung.</p>
        ${items.map((item) => `<article class="order-card" data-orphan="${escapeHtml(item.id)}">
          <div><strong>${escapeHtml(item.member_email || "—")}</strong> · ${formatRupiah(item.amount_idr)} · status: ${escapeHtml(item.status)}${item.resolved_order_id ? ` · order tertaut: <code>${escapeHtml(item.resolved_order_id)}</code>` : ""} · ${escapeHtml(formatDate(item.created_at))}</div>
          <form class="form-grid orphan-resolve-form">
            <label>Paket yang di-grant<select class="orphan-package" required>${pkgOptions}</select></label>
            <label>RRN mutasi (dashboard Cutiezy)<input class="orphan-rrn" maxlength="191" placeholder="opsional, dianjurkan"></label>
            <div class="form-actions"><button class="button button-primary" type="submit">Resolve &amp; grant</button><span class="order-resolve-msg orphan-msg"></span></div>
          </form>
        </article>`).join("")}</div>`;
      $$("#orphan-qr-box .orphan-resolve-form").forEach((form) => {
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          const card = form.closest("[data-orphan]");
          const orphanId = card.dataset.orphan;
          const btn = form.querySelector('button[type="submit"]');
          const msg = form.querySelector(".orphan-msg");
          if (btn) btn.disabled = true;
          if (msg) msg.textContent = "Memproses…";
          try {
            const result = await api(`/v1/admin/orphan-qr/${orphanId}/resolve`, {
              method: "POST",
              body: {
                package_id: form.querySelector(".orphan-package").value,
                mutation_ref: form.querySelector(".orphan-rrn").value || null,
              },
            });
            // Kontrak resolve-berbukti: outcome eksplisit WAJIB
            // ditampilkan apa adanya — jangan menebak dari HTTP 200.
            const outcome = typeof result?.outcome === "string" ? result.outcome.toLowerCase() : "";
            const texts = {
              granted: "Kuota berhasil di-grant.",
              already_granted: "Kuota sudah ter-grant sebelumnya.",
              alreadygranted: "Kuota sudah ter-grant sebelumnya.",
              needs_review: "Grant ditahan (perlu tinjauan) — lanjutkan lewat tombol Grant ulang pada order tertaut.",
              rejected: "Ditolak — check-status membuktikan QR ini belum lunas.",
            };
            if (msg) msg.textContent = texts[outcome] || "Resolve selesai.";
            await loadOrders();
          } catch (error) {
            if (msg) msg.textContent = error.message || "Resolve QR yatim gagal.";
            if (btn) btn.disabled = false;
          }
        });
      });
    } catch (_) {
      box.innerHTML = "";
    }
  }

  // AREA 3: kartu ringkasan rekonsiliasi untuk rentang yang sama
  // dengan filter daftar. Tanpa rentang lengkap, tampilkan petunjuk.
  async function loadRecon() {
    const box = $("#orders-recon");
    if (!box) return;
    const from = $("#orders-from-filter")?.value || "";
    const to = $("#orders-to-filter")?.value || "";
    if (!from || !to) {
      box.innerHTML = `<p class="tester-audit-note">Isi dari &amp; sampai tanggal untuk melihat ringkasan rekonsiliasi (jumlah + nominal per status).</p>`;
      return;
    }
    const data = await api(`/v1/admin/orders/reconciliation?${new URLSearchParams({ from, to }).toString()}`);
    const s = data.summary || {};
    const card = (label, bucket) => `<article class="metric-card"><div><span>${escapeHtml(label)}</span><strong>${formatNumber(bucket?.count || 0)} order</strong><small>${formatRupiah(bucket?.amount_idr || 0)}</small></div></article>`;
    box.innerHTML = card("Menunggu bayar", s.waiting) + card("Lunas (belum grant)", s.paid) + card("Ter-grant", s.granted) + card("Perlu tinjauan", s.needs_review) + card("Kedaluwarsa", s.expired) + card("Dibatalkan", s.canceled) + `<article class="metric-card metric-card-primary"><div><span>Total rentang</span><strong>${formatNumber(s.total_count || 0)} order</strong><small>${formatRupiah(s.total_amount_idr || 0)}</small></div></article>`;
  }

  // AREA 3: status alert Telegram (hanya boolean env ter-set, tanpa secret).
  // K35 (Fase 3): teks kesehatan pengiriman NYATA, bukan sekadar
  // "env ter-set". "Belum pernah mengirim" ditulis eksplisit — panel
  // tidak boleh menampilkan "aktif" yang menyesatkan untuk kondisi itu.
  function alertDeliveryText(data) {
    if (!data) return "";
    const when = data.last_attempt_at ? formatDate(data.last_attempt_at) : "";
    if (data.delivery_state === "never_attempted") return "Belum pernah mengirim (sejak proses berjalan).";
    if (data.delivery_state === "last_failed") return `Pengiriman terakhir GAGAL${when ? ` pada ${when}` : ""}${data.last_attempt_title ? ` (${data.last_attempt_title})` : ""} — periksa token/chat Telegram.`;
    return `Pengiriman terakhir berhasil${when ? ` pada ${when}` : ""}.`;
  }

  async function loadAlertStatus() {
    const el = $("#alert-status");
    if (!el) return;
    const data = await api("/v1/admin/alerts/status");
    el.textContent = data.enabled
      ? `Alert Telegram: terkonfigurasi. ${alertDeliveryText(data)}`
      : `Alert Telegram: nonaktif (env bot/chat belum ter-set; kejadian hanya dicatat di log + aktivitas admin). ${alertDeliveryText(data)}`;
  }

  // B22/B26 (Fase 3): monitor stream + DLQ di panel — operator tahu
  // breaker terbuka, stream melewati ambang, dan DLQ tidak kosong
  // tanpa bergantung pada Telegram.
  async function loadStreamHealth() {
    const box = $("#stream-health-box");
    const note = $("#stream-health-note");
    if (!box) return;
    const data = await api("/v1/admin/stream-health");
    const open = data.breakers_open || [];
    if (note) {
      note.textContent = data.redis_available
        ? `Stream ${data.stream_name}: ${data.stream_length == null ? "—" : formatNumber(data.stream_length)} entri (ambang alarm ${formatNumber(data.stream_warn_threshold)}) · DLQ: ${data.dlq_length == null ? "—" : formatNumber(data.dlq_length)} entri.`
        : "Redis tidak tersedia: panjang stream/DLQ tidak dapat dibaca (angka breaker tetap live dari guard).";
    }
    const chips = [];
    if (data.stream_over_threshold) chips.push(`<span class="ep-sum-chip"><b>Stream melewati ambang!</b> ${formatNumber(data.stream_length)} &gt; ${formatNumber(data.stream_warn_threshold)}</span>`);
    if (data.dlq_non_empty) chips.push(`<span class="ep-sum-chip"><b>DLQ tidak kosong!</b> ${formatNumber(data.dlq_length)} event menunggu replay di bawah.</span>`);
    if (open.length) chips.push(`<span class="ep-sum-chip"><b>Breaker terbuka:</b> ${open.map((item) => escapeHtml(item.endpoint_id)).join(", ")}</span>`);
    if (!chips.length) chips.push(`<span class="ep-sum-chip"><b>Stream &amp; breaker normal</b>${data.redis_available ? ` · ${formatNumber(data.stream_length)} entri stream · DLQ kosong` : " · Redis tidak tersedia"}</span>`);
    chips.push(`<span class="ep-sum-chip"><b>Alert:</b> ${escapeHtml(alertDeliveryText(data.alerts))}</span>`);
    box.innerHTML = chips.join("");
  }

  async function loadTrialMonitor() {
    const box = $("#trial-monitor-box");
    const note = $("#trial-monitor-note");
    const table = $("#trial-monitor-ips");
    if (!box) return;
    const data = await api("/v1/admin/trial-monitor");
    if (note) {
      note.textContent = `Grant 24 jam: ${formatNumber(data.grants_24h)} · 7 hari: ${formatNumber(data.grants_7d)} · total: ${formatNumber(data.total_grants)} · kuota trial 24 jam: ${formatNumber(data.quota_hits_24h)} hit · batas ${data.ip_limit_per_24h} grant/IP/24 jam · ambang waspada ${data.alert_threshold_grants_24h} grant/24 jam.`;
    }
    const chips = [];
    if (data.alert) chips.push(`<span class="ep-sum-chip"><b>Waspada: lonjakan trial!</b> ${data.ips_at_limit_24h ? `${formatNumber(data.ips_at_limit_24h)} IP mencapai batas` : `${formatNumber(data.grants_24h)} grant dalam 24 jam`} — periksa apakah ini farming, bukan blokir otomatis.</span>`);
    if (!chips.length) chips.push(`<span class="ep-sum-chip"><b>Trial normal</b> · ${formatNumber(data.grants_24h)} grant 24 jam · ${formatNumber(data.ips_at_limit_24h)} IP mencapai batas</span>`);
    box.innerHTML = chips.join("");
    if (table) {
      const ips = data.top_ips_24h || [];
      table.innerHTML = ips.length ? ips.map((item) => `<tr>
      <td>${escapeHtml(item.ip)}</td>
      <td><strong>${formatNumber(item.grants)}</strong>${item.grants >= data.ip_limit_per_24h ? ` <span class="status-badge demo">Batas tercapai</span>` : ""}</td>
    </tr>`).join("") : `<tr><td colspan="2" class="empty-state">Belum ada grant trial ber-IP dalam 24 jam (grant lama tanpa IP tidak tampil).</td></tr>`;
    }
  }

  async function loadDlq() {
    const table = $("#dlq-table");
    const note = $("#dlq-note");
    if (!table) return;
    const entries = await api("/v1/admin/dlq");
    if (note) note.textContent = entries.length
      ? `${entries.length} entri DLQ terbaru (maks 100). Replay bersifat idempotent: replay ganda tidak menggandakan riwayat/ledger. Entri yang gagal persist/parse dipertahankan.`
      : "DLQ kosong — tidak ada event yang kehilangan bukti riwayat.";
    table.innerHTML = entries.length ? entries.map((entry) => `<tr>
      <td><strong>${escapeHtml(entry.id)}</strong><br /><small>${escapeHtml(entry.reason || "—")}</small></td>
      <td>${escapeHtml(entry.product || "—")}<br /><small>${escapeHtml(entry.outcome || "—")}</small></td>
      <td>${escapeHtml(entry.api_key_prefix || "—")}<br /><small>${escapeHtml(entry.target_masked || "—")}</small></td>
      <td>${escapeHtml(entry.event_id || entry.source_id || "—")}</td>
      <td><button class="table-action" type="button" data-action="dlq-replay" data-id="${escapeHtml(entry.id)}">Replay</button></td>
    </tr>`).join("") : `<tr><td colspan="5" class="empty-state">DLQ kosong.</td></tr>`;
  }

  async function replayDlq(id) {
    if (!window.confirm(`Replay entri DLQ "${id}"? Event akan dipersist ulang (idempotent) lalu dihapus dari DLQ bila sukses.`)) return;
    try {
      const result = await api(`/v1/admin/dlq/${encodeURIComponent(id)}/replay`, { method: "POST" });
      showToast(`Event ${result.event_id} berhasil di-replay dari DLQ.`, "success");
      await loadDlq();
      await loadStreamHealth();
    } catch (error) {
      handleApiError(error);
    }
  }

  async function replayAllDlq() {
    if (!window.confirm("Replay SEMUA entri DLQ (maks 100)? Entri yang gagal persist/parse akan dipertahankan, bukan dihapus.")) return;
    try {
      const result = await api("/v1/admin/dlq/replay-all", { method: "POST" });
      showToast(`Replay massal DLQ: ${result.replayed} di-replay, ${result.kept} dipertahankan (dari ${result.attempted}).`, "success");
      await loadDlq();
      await loadStreamHealth();
    } catch (error) {
      handleApiError(error);
    }
  }

  // AREA 3: daftar + form pencatatan refund untuk satu order.
  // PENCATATAN SAJA: uang dikembalikan admin lewat dashboard provider
  // secara manual; endpoint ini tidak menggerakkan uang maupun kuota.
  async function renderOrderRefunds(orderId) {
    const box = $("#order-refunds");
    if (!box) return;
    try {
      const refunds = await api(`/v1/admin/orders/${orderId}/refunds`);
      const list = refunds.length === 0
        ? `<p class="tester-audit-note">Belum ada refund tercatat untuk order ini.</p>`
        : `<ul>${refunds.map((r) => `<li>${formatRupiah(r.amount_idr)} · ${escapeHtml(r.reason)}${r.external_ref ? ` · ref: ${escapeHtml(r.external_ref)}` : ""} · oleh ${escapeHtml(r.recorded_by)} · ${escapeHtml(formatDate(r.created_at))}</li>`).join("")}</ul>`;
      box.innerHTML = `<div class="order-section"><h3 class="order-section-title">Refund tercatat</h3>${list}</div>
        <form id="order-refund-form" class="form-grid">
          <label>Nominal refund (Rp)<input id="order-refund-amount" type="number" min="1" required></label>
          <label>Alasan (wajib)<input id="order-refund-reason" maxlength="500" required></label>
          <label>Referensi dashboard provider (opsional)<input id="order-refund-ref" maxlength="191"></label>
          <label>Catatan kompensasi kuota (opsional, hanya catatan)<input id="order-refund-note" maxlength="500"></label>
          <div class="form-actions"><button class="button button-secondary" type="submit">Catat refund</button><span id="order-refund-msg" class="order-resolve-msg"></span></div>
          <p class="tester-audit-note">Hanya pencatatan: pastikan uang sudah dikembalikan lewat dashboard provider. Total refund per order tidak boleh melebihi nominal order; kuota tidak diubah dari sini.</p>
        </form>`;
      $("#order-refund-form")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const msg = $("#order-refund-msg");
        const btn = event.target.querySelector('button[type="submit"]');
        // B11 (panel): tombol submit dinonaktifkan selama permintaan
        // berjalan — klik ganda tidak boleh mencatat refund ganda
        // (server kini juga mengunci baris order, ini lapis keduanya).
        if (btn) btn.disabled = true;
        if (msg) msg.textContent = "Mencatat…";
        try {
          await api(`/v1/admin/orders/${orderId}/refund-record`, {
            method: "POST",
            body: {
              amount_idr: Number($("#order-refund-amount").value),
              reason: $("#order-refund-reason").value,
              external_ref: $("#order-refund-ref").value || null,
              compensation_note: $("#order-refund-note").value || null,
            },
          });
          if (msg) msg.textContent = "Refund tercatat.";
          await renderOrderRefunds(orderId);
        } catch (error) {
          if (msg) msg.textContent = error.message || "Pencatatan refund gagal.";
          if (btn) btn.disabled = false;
        }
      });
    } catch (error) {
      box.innerHTML = `<p class="tester-audit-note">Daftar refund tidak dapat dimuat.</p>`;
    }
  }

  function renderOrders() {
    const statusLabel = {
      waiting_payment: "Menunggu bayar",
      paid: "Lunas (belum grant)",
      granted: "Ter-grant",
      expired: "Kedaluwarsa",
      canceled: "Dibatalkan",
      needs_review: "Perlu tinjauan",
    };
    const page = Math.floor(state.ordersPage.offset / state.ordersPage.limit) + 1;
    $("#orders-count").textContent = `${formatNumber(state.orders.length)} order · halaman ${page}`;
    const from = state.orders.length === 0 ? 0 : state.ordersPage.offset + 1;
    const to = state.ordersPage.offset + state.orders.length;
    const info = $("#orders-page-info");
    if (info) info.textContent = `Menampilkan ${formatNumber(from)}–${formatNumber(to)} (halaman ${page})`;
    const prev = $("#orders-prev");
    const next = $("#orders-next");
    if (prev) prev.disabled = state.ordersPage.offset <= 0;
    if (next) next.disabled = state.orders.length < state.ordersPage.limit;
    $("#orders-empty").hidden = state.orders.length > 0;
    $("#orders-table").innerHTML = state.orders.map((order) => `<tr>
      <td data-label="Waktu">${escapeHtml(formatDate(order.created_at))}</td>
      <td data-label="Member"><strong>${escapeHtml(order.member_email || "—")}</strong></td>
      <td data-label="Paket">${escapeHtml(order.package_name)}</td>
      <td data-label="Nominal">${formatRupiah(order.amount_idr)}</td>
      <td data-label="Status"><span class="status-badge ${order.status === "granted" ? "valid" : order.status === "needs_review" ? "invalid" : ""}">${escapeHtml(statusLabel[order.status] || order.status)}</span></td>
      <td data-label="Aksi"><button class="button button-secondary" type="button" data-order-detail="${escapeHtml(order.id)}">Detail</button></td>
    </tr>`).join("");
    $$("#orders-table [data-order-detail]").forEach((button) => {
      button.addEventListener("click", () => showOrderDetail(button.dataset.orderDetail));
    });
  }

  async function showOrderDetail(orderId) {
    try {
      const order = await api(`/v1/admin/orders/${orderId}`);
      const statusLabel = {
        waiting_payment: "Menunggu bayar",
        paid: "Lunas (belum grant)",
        granted: "Ter-grant",
        expired: "Kedaluwarsa",
        canceled: "Dibatalkan",
        needs_review: "Perlu tinjauan",
      };
      const statusBadge = {
        waiting_payment: "pending",
        paid: "pending",
        granted: "valid",
        expired: "inactive",
        canceled: "inactive",
        needs_review: "pending",
      };
      $("#order-detail-title").textContent = `${order.package_name} — ${formatRupiah(order.amount_idr)}`;
      const grantedInfo = order.granted_at ? `${escapeHtml(formatDate(order.granted_at))} · +${formatNumber(order.granted_quota || 0)} hit · aktif s/d ${order.granted_expires_at ? escapeHtml(formatDate(order.granted_expires_at)) : "—"}` : "—";
      // last_error tidak dibersihkan saat grant sukses (menjadi
      // "Grant ulang oleh admin"), jadi callout hanya untuk needs_review.
      const showCallout = order.status === "needs_review" && !!order.last_error;
      // B14: total refund tercatat ditampilkan di samping tombol Grant
      // ulang — grant diblokir server bila total sudah penuh.
      let refundTotal = 0;
      try {
        const refunds = await api(`/v1/admin/orders/${orderId}/refunds`);
        refundTotal = refunds.reduce((sum, r) => sum + (Number(r.amount_idr) || 0), 0);
      } catch (_) { /* total opsional; form refund memuat daftarnya sendiri */ }
      const refundFull = refundTotal > 0 && refundTotal >= order.amount_idr;
      const refundNote = refundTotal > 0 ? `<span class="order-resolve-msg">Total refund tercatat: ${formatRupiah(refundTotal)}${refundFull ? " — sudah penuh, grant diblokir server sampai refund-record dikoreksi." : ""}</span>` : "";
      const mismatch = (order.last_error || "").includes("Nominal bayar tidak sama");
      const resolveBtnHtml = (label) => `<button class="button button-primary" type="button" id="order-resolve-btn">${label}</button><span id="order-resolve-msg" class="order-resolve-msg"></span>`;
      let heroAction = "";
      if (order.status === "needs_review") {
        heroAction = mismatch
          ? `<span class="order-resolve-msg">Penanganan manual: nominal tidak sama.</span>`
          : resolveBtnHtml("Grant ulang");
      } else if (order.status === "expired" || order.status === "canceled") {
        // B10: tombol resolve untuk order terminal yang ternyata lunas
        // (bayar telat) — server re-check Cutiezy dulu dan hanya
        // meng-grant bila terbukti Paid + nominal cocok.
        heroAction = mismatch
          ? `<span class="order-resolve-msg">Penanganan manual: nominal tidak sama.</span>`
          : resolveBtnHtml("Grant ulang (cek bayar telat)");
      }
      if (heroAction && refundNote) heroAction += refundNote;
      $("#order-detail-body").innerHTML = `
        <div class="order-hero">
          <div class="order-hero-main">
            <span class="status-badge ${statusBadge[order.status] || ""}">${escapeHtml(statusLabel[order.status] || order.status)}</span>
            <div class="order-hero-id">Order <code>${escapeHtml(order.id)}</code></div>
          </div>
          ${heroAction ? `<div class="order-hero-action">${heroAction}</div>` : ""}
        </div>
        ${showCallout ? `<div class="order-callout">${escapeHtml(order.last_error)}</div>` : ""}
        <div class="order-section">
          <h3 class="order-section-title">Pembeli &amp; Paket</h3>
          <div class="order-fields">
            <div class="order-field"><span class="order-field-label">Member</span><span class="order-field-value">${escapeHtml(order.member_email || "—")}</span></div>
            <div class="order-field"><span class="order-field-label">Kuota paket</span><span class="order-field-value">${formatNumber(order.quota_hits)} hit · ${formatNumber(order.rate_limit_per_minute)}/mnt · ${formatNumber(order.valid_days)} hari</span></div>
          </div>
        </div>
        <div class="order-section">
          <h3 class="order-section-title">Pembayaran</h3>
          <div class="order-fields">
            <div class="order-field span-2"><span class="order-field-label">Token QRIS</span><span class="order-field-value mono">${escapeHtml(order.qris_token || "—")}</span></div>
            <div class="order-field"><span class="order-field-label">QR berlaku s/d</span><span class="order-field-value">${order.qris_expires_at ? escapeHtml(formatDate(order.qris_expires_at)) : "—"}</span></div>
            <div class="order-field"><span class="order-field-label">Dibayar</span><span class="order-field-value">${order.paid_at ? escapeHtml(formatDate(order.paid_at)) : "—"}</span></div>
            <div class="order-field"><span class="order-field-label">Ter-grant</span><span class="order-field-value">${grantedInfo}</span></div>
            <div class="order-field"><span class="order-field-label">Referensi mutasi</span><span class="order-field-value mono">${escapeHtml(order.mutation_ref || "—")}</span></div>
            <div class="order-field"><span class="order-field-label">Total refund tercatat</span><span class="order-field-value">${formatRupiah(refundTotal)}</span></div>
          </div>
        </div>`;
      $("#order-detail").hidden = false;
      // AREA 3: form refund-record untuk order yang pernah lunas.
      // K23: gerbang server kini status paid/granted ATAU paid_at —
      // form ditampilkan untuk ketiganya (server tetap menolak yang
      // tak-lunas).
      if (order.paid_at || order.status === "paid" || order.status === "granted") {
        $("#order-detail-body").insertAdjacentHTML("beforeend", `<div id="order-refunds"></div>`);
        renderOrderRefunds(orderId).catch(() => {});
      }
      const resolveBtn = $("#order-resolve-btn");
      if (resolveBtn) {
        resolveBtn.addEventListener("click", async () => {
          resolveBtn.disabled = true;
          const msg = $("#order-resolve-msg");
          if (msg) msg.textContent = "Memproses…";
          try {
            // Kontrak resolve (area QRIS): respons membawa field
            // `outcome` eksplisit; bila tidak ada (kontrak lama),
            // fallback ke status view seperti sebelumnya — kebenaran
            // ada di sana, bukan di status HTTP (200 apa pun hasilnya).
            const result = await api(`/v1/admin/orders/${orderId}/resolve`, { method: "POST" });
            const outcome = typeof result?.outcome === "string" ? result.outcome.toLowerCase() : "";
            const granted = result && (outcome === "granted" || outcome === "already_granted" || outcome === "alreadygranted" || (!result.outcome && result.status === "granted"));
            await loadOrders();
            await showOrderDetail(orderId);
            // Setelah render ulang, tombol+pesan hanya ada bila order
            // masih needs_review/expired/canceled; bila ter-grant,
            // badge-nya sendiri yang berbicara. Outcome WAJIB
            // ditampilkan apa adanya (B10): "belum berhasil" generik
            // menyembunyikan beda rejected (terbukti belum lunas) vs
            // needs_review (tertahan) vs expired (tetap terminal).
            const outcomeTexts = {
              granted: "Kuota berhasil di-grant.",
              already_granted: "Kuota sudah ter-grant sebelumnya.",
              alreadygranted: "Kuota sudah ter-grant sebelumnya.",
              needs_review: "Grant ditahan (perlu tinjauan) — kuota belum di-grant.",
              rejected: "Ditolak — order terbukti belum lunas, kuota tidak di-grant.",
              expired: "Order tetap kedaluwarsa — kuota tidak di-grant.",
              canceled: "Order tetap dibatalkan — kuota tidak di-grant.",
              waiting: "Order masih menunggu bayar — kuota tidak di-grant.",
            };
            const msgAfter = $("#order-resolve-msg");
            if (msgAfter) msgAfter.textContent = outcomeTexts[outcome] || (granted ? "Kuota berhasil di-grant." : "Grant belum berhasil.");
          } catch (error) {
            if (msg) msg.textContent = error.message || "Grant ulang gagal.";
            resolveBtn.disabled = false;
          }
        });
      }
    } catch (error) {
      handleApiError(error);
    }
  }

  // AREA 1: analitik riil. Total pendapatan di sini = jumlah kolom
  // per-hari (keduanya dalam rentang yang sama); total sepanjang masa
  // tetap di kartu Ringkasan. Tanpa database, backend mengembalikan
  // angka nol — panel menandainya "tanpa database", bukan "nol".
  async function loadAnalytics() {
    state.analytics = await api(`/v1/admin/analytics?days=${state.analyticsDays}`);
    renderAnalytics();
  }

  function renderAnalytics() {
    const data = state.analytics;
    if (!data) return;
    const meta = $("#analytics-meta");
    if (meta) meta.textContent = `${data.days} hari · ${data.cached ? "cache 60 detik" : "data baru"}${data.database ? "" : " · tanpa database"}`;
    const note = $("#analytics-note");
    if (note) note.textContent = data.database
      ? "Pendapatan = order paid + granted dalam rentang ini. Success rate = valid + belum KYC dibanding hasil final."
      : "Tidak ada koneksi database: angka di bawah berarti belum diketahui, bukan nol.";
    $("#analytics-revenue-total").textContent = formatRupiah(data.revenue.total_idr);
    $("#analytics-revenue-orders").textContent = `${formatNumber(data.revenue.total_orders)} order lunas`;
    const totalHits = data.products.reduce((sum, product) => sum + Number(product.total_hits || 0), 0);
    $("#analytics-hits-total").textContent = formatNumber(totalHits);
    $("#analytics-revenue-daily").textContent = formatRupiah(data.days > 0 ? Math.round(data.revenue.total_idr / data.days) : 0);
    const chart = $("#analytics-revenue-chart");
    const maxRevenue = Math.max(...data.revenue.per_day.map((day) => Number(day.revenue_idr || 0)), 1);
    chart.innerHTML = data.revenue.per_day.length ? data.revenue.per_day.map((day) => {
      const height = Math.max(2, Math.round((Number(day.revenue_idr || 0) / maxRevenue) * 100));
      return `<div class="analytics-bar" title="${escapeHtml(day.day)}: ${escapeHtml(formatRupiah(day.revenue_idr))} (${formatNumber(day.orders)} order)"><div class="analytics-bar-fill" style="height:${height}%"></div><span>${escapeHtml(day.label)}</span></div>`;
    }).join("") : `<div class="empty-state">Belum ada pendapatan dalam rentang ini.</div>`;
    $("#analytics-revenue-table").innerHTML = data.revenue.per_day.map((day) => `<tr>
      <td>${escapeHtml(day.day)}</td><td>${formatRupiah(day.revenue_idr)}</td><td>${formatNumber(day.orders)}</td>
    </tr>`).join("") || `<tr><td colspan="3" class="empty-state">Belum ada data.</td></tr>`;
    $("#analytics-product-table").innerHTML = data.products.map((product) => `<tr>
      <td data-label="Produk"><strong>${escapeHtml(product.product_label === product.product ? productLabel(product.product) : product.product_label)}</strong></td>
      <td data-label="Total hit">${formatNumber(product.total_hits)}</td>
      <td data-label="Hasil final">${formatNumber(product.final_hits)}</td>
      <td data-label="Sukses (valid + belum KYC)">${formatNumber(product.success_hits)}</td>
      <td data-label="Success rate">${product.success_rate_percent == null ? "—" : `${Number(product.success_rate_percent).toLocaleString("id-ID", { maximumFractionDigits: 1 })}%`}</td>
      <td data-label="Rata-rata latensi">${product.avg_latency_ms == null ? "—" : `${formatNumber(product.avg_latency_ms)} ms`}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="empty-state">Belum ada data.</td></tr>`;
    const byDay = {};
    data.hits_per_day.forEach((row) => {
      if (!byDay[row.day]) byDay[row.day] = { bank_account: 0, ewallet: 0, whatsapp: 0, pln: 0 };
      if (byDay[row.day][row.product] !== undefined) byDay[row.day][row.product] += Number(row.hits || 0);
    });
    $("#analytics-hits-table").innerHTML = Object.keys(byDay).sort().map((day) => {
      const row = byDay[day];
      const total = row.bank_account + row.ewallet + row.whatsapp + row.pln;
      return `<tr><td>${escapeHtml(day)}</td><td>${formatNumber(row.bank_account)}</td><td>${formatNumber(row.ewallet)}</td><td>${formatNumber(row.whatsapp)}</td><td>${formatNumber(row.pln)}</td><td><strong>${formatNumber(total)}</strong></td></tr>`;
    }).join("") || `<tr><td colspan="6" class="empty-state">Belum ada data.</td></tr>`;
  }

  // AREA 2: kesehatan rute — selalu live (breaker tidak di-cache).
  // Failover memakai endpoint PATCH .../active yang sama dengan saklar
  // daftar server; aksinya sudah tercatat di audit admin server-side.
  async function loadProviderHealth() {
    state.providerHealth = await api("/v1/admin/providers/health");
    renderProviderHealth();
  }

  function circuitLabel(circuit) {
    return { closed: "Tertutup", open: "Terbuka", half_open: "Setengah terbuka", unknown: "Tidak diketahui" }[circuit] || circuit;
  }

  function renderProviderHealth() {
    const data = state.providerHealth;
    if (!data) return;
    const note = $("#provider-health-note");
    if (note) note.textContent = data.ledger_available
      ? `Jendela ${data.window_hours} jam terakhir · data breaker live.`
      : `Jendela ${data.window_hours} jam terakhir · agregat ledger tidak tersedia (data breaker tetap live).`;
    const productsEl = $("#provider-health-products");
    if (productsEl) productsEl.innerHTML = data.products.map((product) => `<span class="ep-sum-chip"><b>${escapeHtml(product.product_label === product.product ? productLabel(product.product) : product.product_label)}</b> ${formatNumber(product.total_hits)} hit · ${product.success_rate_percent == null ? "—" : `${Number(product.success_rate_percent).toLocaleString("id-ID", { maximumFractionDigits: 1 })}% sukses`} · rata-rata ${product.avg_latency_ms == null ? "—" : `${formatNumber(product.avg_latency_ms)} ms`} · p95 ${product.p95_latency_ms == null ? "—" : `${formatNumber(product.p95_latency_ms)} ms`} · ${formatNumber(product.provider_errors)} error</span>`).join("");
    $("#provider-health-table").innerHTML = data.routes.length ? data.routes.map((route) => `<tr>
      <td><strong>${escapeHtml(route.route_label)}</strong><br /><small>${escapeHtml(route.endpoint_id)}</small></td>
      <td>${escapeHtml(route.product_label === route.product ? productLabel(route.product) : route.product_label)}</td>
      <td>${route.active ? "Aktif" : "Nonaktif"}</td>
      <td><span class="status-badge ${route.circuit === "open" ? "inactive" : route.circuit === "half_open" ? "demo" : "active"}">${escapeHtml(circuitLabel(route.circuit))}</span></td>
      <td>${formatNumber(route.consecutive_failures)}</td>
      <td><button class="table-action ${route.active ? "danger" : ""}" type="button" data-action="health-toggle-provider" data-id="${escapeHtml(route.endpoint_id)}">${route.active ? "Nonaktifkan" : "Aktifkan"}</button></td>
    </tr>`).join("") : `<tr><td colspan="6" class="empty-state">Belum ada rute provider.</td></tr>`;
  }

  async function toggleHealthProvider(id) {
    const route = state.providerHealth ? state.providerHealth.routes.find((item) => item.endpoint_id === id) : null;
    const active = route ? !route.active : true;
    const label = route ? route.route_label : "rute ini";
    if (!window.confirm(active
      ? `Aktifkan rute "${label}"? Rute ini akan kembali menerima validasi dan circuit breaker-nya direset.`
      : `Nonaktifkan rute "${label}"? Validasi tidak lagi memakai rute ini sampai diaktifkan lagi.`)) return;
    try {
      const endpoint = await api(`/v1/admin/provider-endpoints/${id}/active`, { method: "PATCH", body: { active } });
      const index = state.providers.findIndex((item) => item.id === endpoint.id);
      if (index >= 0) state.providers[index] = endpoint; else state.providers.push(endpoint);
      renderProviders();
      await loadProviderHealth();
      showToast(`Rute ${endpoint.name} ${active ? "diaktifkan" : "dinonaktifkan"} (tercatat di audit).`, "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  // AREA 6: pengumuman + maintenance (GET/PUT /v1/admin/site-settings).
  // Teks diisi lewat .value (bukan innerHTML); panel admin adalah
  // permukaan admin-only, bukan publik.
  async function loadSiteSettings() {
    const settings = await api("/v1/admin/site-settings").catch(() => null);
    if (!settings) return;
    $("#site-announcement-text").value = settings.announcement_text || "";
    $("#site-announcement-active").checked = !!settings.announcement_active;
    $("#site-maintenance-banner-text").value = settings.maintenance_banner_text || "";
    $("#site-maintenance-banner-active").checked = !!settings.maintenance_banner_active;
    $("#site-maintenance-block").checked = !!settings.maintenance_block_validations;
    $("#site-settings-status").textContent = settings.maintenance_block_validations
      ? "PERHATIAN: blokir validasi sedang AKTIF — endpoint validasi menjawab 503."
      : "Blokir validasi nonaktif.";
  }

  async function loadQrisSettings() {
    const settings = await api("/v1/admin/qris/settings").catch(() => null);
    if (!settings) return;
    $("#qris-enabled").checked = !!settings.enabled;
    $("#qris-expiry").value = String(settings.expiry_minutes);
    $("#qris-valid-days").value = settings.valid_days;
    $("#qris-source-id").value = settings.source_id ?? "";
    const parts = [
      settings.has_api_key ? "API key tersimpan" : "API key belum diisi",
      settings.has_webhook_secret ? "webhook secret tersimpan" : "webhook secret belum diisi",
    ];
    if (settings.last_cutiezy_remaining != null) parts.push(`sisa kuota Cutiezy: ${formatNumber(settings.last_cutiezy_remaining)} hit`);
    if (settings.last_error) parts.push(`error terakhir: ${settings.last_error}`);
    $("#qris-status").textContent = parts.join(" · ");
  }

  // Notifikasi bot Telegram admin: token tidak pernah ditampilkan
  // (hanya status + 4 akhir); chat ID ditampilkan karena bukan
  // kredensial dan admin perlu memverifikasi chat tujuannya.
  async function loadTelegramSettings() {
    const settings = await api("/v1/admin/telegram-settings").catch(() => null);
    if (!settings) return;
    $("#telegram-chat-id").value = settings.chat_id ?? "";
    const parts = [];
    if (settings.configured) {
      parts.push("Terkonfigurasi");
    } else if (settings.has_bot_token || settings.chat_id) {
      parts.push("Belum lengkap (isi token + chat ID)");
    } else {
      parts.push("Belum dikonfigurasi — notifikasi dormant");
    }
    if (settings.has_bot_token) parts.push(`token tersimpan${settings.bot_token_tail ? ` (••••${settings.bot_token_tail})` : ""}`);
    if (settings.chat_id) parts.push(`chat ID ${settings.chat_id}`);
    $("#telegram-status").textContent = parts.join(" · ");
    $("#telegram-webhook-status").textContent = settings.configured
      ? (settings.webhook_active ? "Perintah bot aktif — kirim /stats dari Telegram." : "Perintah bot belum aktif — tekan “Aktifkan perintah bot”.")
      : "Perintah bot belum aktif (Telegram belum lengkap).";
  }

  const EYE_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  const EYE_OFF_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
  let memberKeyMasked = "—", memberKeyFull = null, memberKeyShown = false;

  function openMemberManage(memberId) {
    const member = state.members.find((entry) => entry.id === memberId);
    if (!member) return;
    state.managedMemberId = memberId;
    $("#member-manage-title").textContent = member.name || member.email;
    const planLabel = { trial: "Trial", package: "Paket", manual: "Manual", umum: "Umum" };
    const planEffective = member.plan_effective || member.plan_kind;
    $("#member-manage-sub").textContent = `${member.email} · ${member.status === "active" ? "Aktif" : "Nonaktif"} · Plan ${planLabel[planEffective] || planEffective}`;
    $("#member-manage-panel").hidden = false;
    // Formulir selalu mulai bersih agar nilai member sebelumnya tidak
    // terbawa ke member yang baru dibuka.
    $("#member-assign-rate").value = "";
    $("#member-assign-days").value = 30;
    $("#member-assign-mode").value = "replace";
    $("#member-assign-hits").value = "";
    memberKeyMasked = member.key_prefix ? `${member.key_prefix}_••••••••••••` : "—";
    memberKeyFull = null;
    memberKeyShown = false;
    $("#member-key-masked").textContent = memberKeyMasked;
    $("#member-key-eye").innerHTML = EYE_SVG;
    $("#member-key-eye").title = "Lihat kunci";
    $("#member-key-copy").hidden = true;
    $("#member-key-note").hidden = true;
    $("#member-rate-value").value = member.rate_limit_per_minute || "";
    $("#member-toggle-status").textContent = member.status === "active" ? "Nonaktifkan member" : "Aktifkan member";
    $("#member-new-key").hidden = true;
    $("#member-assign-source").value = "package";
    $("#member-assign-package-wrap").hidden = false;
    $("#member-assign-hits-wrap").hidden = true;
    $("#member-manage-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ---- Detail member lengkap + adjust kuota manual (Area 4) ----
  async function openMemberDetail(memberId) {
    state.memberDetailPage.offset = 0;
    try {
      await loadMemberDetail(memberId);
      $("#member-detail-panel").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      handleApiError(error);
    }
  }

  async function loadMemberDetail(memberId) {
    const params = new URLSearchParams({
      days: "30",
      limit: String(state.memberDetailPage.limit),
      offset: String(state.memberDetailPage.offset),
    });
    const detail = await api(`/v1/admin/members/${memberId}/detail?${params.toString()}`);
    state.memberDetail = detail;
    renderMemberDetail();
  }

  function renderMemberDetail() {
    const detail = state.memberDetail;
    if (!detail) return;
    const member = detail.member;
    const planLabel = { trial: "Trial", package: "Paket", manual: "Manual", umum: "Umum" };
    const planEffective = member.plan_effective || member.plan_kind;
    $("#member-detail-title").textContent = member.name || member.email;
    $("#member-detail-sub").textContent = `${member.email} · Kode member: ${member.member_code || "—"} · ${member.status === "active" ? "Aktif" : "Nonaktif"} · Plan ${planLabel[planEffective] || planEffective} · Daftar ${formatDate(member.created_at)} · Login terakhir ${member.last_login_at ? formatDate(member.last_login_at) : "—"}`;
    // Formulir ubah email selalu mulai bersih agar nilai member
    // sebelumnya tidak terbawa; onclick (bukan addEventListener) agar
    // render ulang tidak menumpuk handler.
    $("#member-email-new").value = "";
    $("#member-email-change-result").textContent = "";
    $("#member-email-change").onclick = submitMemberEmailChange;
    $("#member-detail-panel").hidden = false;
    const statusLabel = { active: "Aktif", disabled: "Nonaktif", revoked: "Dicabut" };
    $("#member-detail-keys").innerHTML = detail.keys.length ? detail.keys.map((key) => `<tr>
      <td data-label="Kunci"><code>${escapeHtml(key.prefix)}</code><br /><span class="tester-audit-note">${escapeHtml(key.name)}</span></td>
      <td data-label="Status"><span class="status-badge ${key.status === "active" ? "valid" : "invalid"}">${escapeHtml(statusLabel[key.status] || key.status)}</span></td>
      <td data-label="Kuota">${formatNumber(key.quota_remaining)} / ${formatNumber(key.quota_total)}</td>
      <td data-label="Aktif s/d">${key.expires_at ? escapeHtml(formatDate(key.expires_at)) : "—"}</td>
      <td data-label="Rate limit">${key.rate_limit_per_minute == null ? "—" : `${formatNumber(key.rate_limit_per_minute)}/mnt`}</td>
      <td data-label="Gratis invalid hari ini">${formatNumber(key.invalid_free_used_today)} / 100 hari ini</td>
      <td data-label="Adjust kuota manual">${key.status === "active" && member.status === "active" ? `<form class="member-adjust-form" data-adjust-key="${escapeHtml(key.id)}">
        <input type="number" step="1" placeholder="+250 / -50" required aria-label="Delta kuota" />
        <input type="text" maxlength="500" placeholder="Alasan (min. 5 karakter)" required aria-label="Alasan adjust" />
        <button class="button button-secondary" type="submit">Adjust</button>
      </form><p class="tester-audit-note" data-adjust-result="${escapeHtml(key.id)}"></p>` : `<span class="tester-audit-note">Adjust hanya untuk kunci aktif milik member aktif.</span>`}</td>
    </tr>`).join("") : `<tr><td colspan="7" class="tester-audit-note">Member ini belum memiliki kunci.</td></tr>`;
    $$("#member-detail-keys [data-adjust-key]").forEach((form) => {
      form.addEventListener("submit", (event) => submitMemberAdjust(event, form.dataset.adjustKey));
    });
    /* Bucket kuota (FIFO): tampil hanya bila detail mengirim buckets[]
       (atau buckets[] per kunci). Tanpa buckets[], seksi tersembunyi dan
       tabel kunci agregat tetap tampil — tidak ada crash. */
    const detailBuckets = Array.isArray(detail.buckets)
      ? detail.buckets
      : detail.keys.flatMap((key) => Array.isArray(key.buckets) ? key.buckets : []);
    const bucketsWrap = $("#member-detail-buckets-wrap");
    if (bucketsWrap) {
      bucketsWrap.hidden = detailBuckets.length === 0;
      $("#member-detail-buckets").innerHTML = detailBuckets.length ? [...detailBuckets].sort((a, b) => {
        if (!a.expires_at) return 1;
        if (!b.expires_at) return -1;
        return new Date(a.expires_at) - new Date(b.expires_at);
      }).map((bucket) => `<div class="member-bucket-row"><span class="member-bucket-name">${escapeHtml(bucket.package_name || "Paket")}</span><span class="member-bucket-hits">${formatNumber(bucket.remaining_hits || 0)} / ${formatNumber(bucket.total_hits || 0)} hit</span><span class="tester-audit-note" style="margin:0;">${bucket.expires_at ? `s/d ${escapeHtml(formatDate(bucket.expires_at))}` : "Tanpa kedaluwarsa"}</span></div>`).join("") : "";
    }
    const orderLabel = { waiting_payment: "Menunggu bayar", paid: "Lunas (belum grant)", granted: "Ter-grant", expired: "Kedaluwarsa", canceled: "Dibatalkan", needs_review: "Perlu tinjauan" };
    $("#member-detail-orders").innerHTML = detail.orders.length ? detail.orders.map((order) => `<tr>
      <td data-label="Waktu">${escapeHtml(formatDate(order.created_at))}</td>
      <td data-label="Paket">${escapeHtml(order.package_name)}</td>
      <td data-label="Nominal">${formatRupiah(order.amount_idr)}</td>
      <td data-label="Status"><span class="status-badge ${order.status === "granted" ? "valid" : order.status === "needs_review" ? "invalid" : ""}">${escapeHtml(orderLabel[order.status] || order.status)}</span></td>
      <td data-label="Grant">${order.granted_quota == null ? "—" : `+${formatNumber(order.granted_quota)} hit`}</td>
    </tr>`).join("") : `<tr><td colspan="5" class="tester-audit-note">Belum ada order.</td></tr>`;
    $("#member-detail-orders-info").textContent = `Menampilkan ${formatNumber(detail.orders.length)} order${detail.orders_has_more ? " (masih ada halaman berikut)" : ""}`;
    $("#member-detail-orders-prev").disabled = detail.orders_offset <= 0;
    $("#member-detail-orders-next").disabled = !detail.orders_has_more;
    const maxUsage = Math.max(1, ...detail.usage.map((day) => day.charged_hits));
    $("#member-detail-usage-note").textContent = detail.usage_source === "ledger"
      ? `Total ${formatNumber(detail.usage_total_charged)} hit tertagih dalam ${detail.usage_days} hari terakhir (dari ledger; hit gratis pool invalid tidak masuk hitungan ini).`
      : "Pemakaian tidak tersedia (database tidak terhubung).";
    $("#member-detail-usage").innerHTML = detail.usage.map((day) => `<div class="member-usage-row"><span>${escapeHtml(day.date)}</span><span class="member-usage-bar"><span style="width:${Math.round((day.charged_hits / maxUsage) * 100)}%"></span></span><strong>${formatNumber(day.charged_hits)}</strong></div>`).join("");
  }

  async function submitMemberEmailChange() {
    const detail = state.memberDetail;
    if (!detail) return;
    const member = detail.member;
    const input = $("#member-email-new");
    const result = $("#member-email-change-result");
    const next = (input.value || "").trim().toLowerCase();
    if (!next) { showToast("Isi email baru dulu.", "error"); return; }
    if (next === member.email) { showToast("Email baru sama dengan email sekarang.", "error"); return; }
    const hasActiveKey = detail.keys.some((key) => key.status === "active");
    const ok = window.confirm(
      `Ubah email member dari ${member.email} ke ${next}?\n\n` +
      (hasActiveKey
        ? "Kunci lama tetap berlaku; tidak ada kunci baru yang diterbitkan karena member sudah memiliki kunci aktif."
        : "Kunci baru format rc_ akan diterbitkan sebagai tambahan (kunci lama tetap berlaku bila ada).") +
      "\n\nLogin Google lama member akan putus; member login lagi dengan akun Google baru."
    );
    if (!ok) return;
    try {
      const changed = await api(`/v1/admin/members/${member.id}/email`, { method: "POST", body: { email: next } });
      await openMemberDetail(member.id);
      if (changed.new_api_key) {
        result.innerHTML = `Email diubah ke <strong>${escapeHtml(changed.new_email)}</strong>. Kunci baru (hanya tampil sekali, sampaikan ke member): <code>${escapeHtml(changed.new_api_key)}</code>`;
      } else {
        result.textContent = `Email diubah ke ${changed.new_email}. Kunci lama tetap berlaku; tidak ada kunci baru yang diterbitkan.`;
      }
      showToast("Email member diubah.", "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  async function submitMemberAdjust(event, keyId) {
    event.preventDefault();
    const detail = state.memberDetail;
    if (!detail) return;
    const form = event.target;
    const deltaInput = form.querySelector("input[type=number]");
    const reasonInput = form.querySelector("input[type=text]");
    const delta = Number(deltaInput.value);
    const reason = reasonInput.value.trim();
    const resultNote = document.querySelector(`[data-adjust-result="${CSS.escape(keyId)}"]`);
    if (!Number.isInteger(delta) || delta === 0) {
      if (resultNote) resultNote.textContent = "Delta harus bilangan bulat bukan 0 (positif menambah, negatif mengurangi).";
      return;
    }
    if (reason.length < 5) {
      if (resultNote) resultNote.textContent = "Alasan wajib diisi, minimal 5 karakter.";
      return;
    }
    if (!window.confirm(`Adjust kuota ${delta > 0 ? "+" : ""}${formatNumber(delta)} hit untuk kunci member ${detail.member.email}? Alasan: ${reason}`)) return;
    try {
      const result = await api(`/v1/admin/members/${detail.member.id}/keys/${keyId}/adjust`, {
        method: "POST",
        body: JSON.stringify({ delta, reason }),
      });
      if (resultNote) resultNote.textContent = `Berhasil: sisa ${formatNumber(result.quota_remaining_before)} → ${formatNumber(result.quota_remaining_after)}, total ${formatNumber(result.quota_total_before)} → ${formatNumber(result.quota_total_after)}.`;
      showToast("Kuota member disesuaikan.", "success");
      await loadMembers();
      await loadMemberDetail(detail.member.id);
    } catch (error) {
      if (resultNote) resultNote.textContent = error.message || "Adjust gagal.";
      handleApiError(error);
    }
  }

  function renderGuard() {
    const form = $("#guard-form");
    if (!form) return;
    const guard = state.guard;
    $("#guard-unavailable").hidden = Boolean(guard);
    form.hidden = !guard;
    if (!guard) {
      $("#guard-products").innerHTML = "";
      $("#guard-persisted-note").textContent = "";
      return;
    }
    const settings = guard.settings;
    $("#guard-max-concurrency").value = settings.max_concurrency_per_product;
    $("#guard-max-concurrency-pln").value = settings.max_concurrency_pln ?? 3;
    $("#guard-queue-wait").value = settings.queue_wait_ms;
    $("#guard-failure-threshold").value = settings.failure_threshold;
    $("#guard-cooldown").value = settings.cooldown_seconds;
    $("#guard-max-attempts").value = settings.max_attempts ?? 2;
    $("#guard-pace-interval").value = settings.pace_interval_ms ?? 334;
    $("#guard-pace-max-wait").value = settings.pace_max_wait_ms ?? 10000;
    const circuitLabel = { closed: "Normal", open: "Terbuka", half_open: "Setengah terbuka" };
    $("#guard-products").innerHTML = guard.products.map((item) => `<div><span>${escapeHtml(productLabel(item.product))} · ${escapeHtml(circuitLabel[item.circuit] || item.circuit)}</span><strong>${formatNumber(item.in_flight)}/${formatNumber(item.max_concurrency)} berjalan</strong><span>${formatNumber(item.consecutive_failures)} gagal berurutan</span></div>`).join("");
  }

  async function submitGuard(event) {
    event.preventDefault();
    const payload = {
      max_concurrency_per_product: Number($("#guard-max-concurrency").value),
      max_concurrency_pln: Number($("#guard-max-concurrency-pln").value),
      queue_wait_ms: Number($("#guard-queue-wait").value),
      failure_threshold: Number($("#guard-failure-threshold").value),
      cooldown_seconds: Number($("#guard-cooldown").value),
      max_attempts: Number($("#guard-max-attempts").value),
      pace_interval_ms: Number($("#guard-pace-interval").value),
      pace_max_wait_ms: Number($("#guard-pace-max-wait").value),
    };
    try {
      const saved = await api("/v1/admin/provider-guard", { method: "PUT", body: payload });
      state.guard = saved;
      renderGuard();
      $("#guard-persisted-note").textContent = saved.persisted
        ? "Tersimpan di database — tetap berlaku setelah restart."
        : "Aktif sekarang, tetapi hanya tersimpan di memori proses (database tidak terhubung) — nilai kembali ke env setelah restart.";
      showToast("Pengaturan provider guard diperbarui dan langsung aktif.", "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  function renderSettings() {
    const session = state.session;
    $("#google-status").textContent = session?.google_login_configured ? "Siap digunakan" : "Perlu dikonfigurasi";
    $("#google-status").className = `settings-status ${session?.google_login_configured ? "" : "status-badge demo"}`;
    $("#provider-status").textContent = state.overview?.demo_mode ? "Mode demo aktif" : "Rute HTTP aktif";
    renderGuard();
    $("#provider-status").className = `settings-status ${state.overview?.demo_mode ? "status-badge demo" : ""}`;
  }

  function openPackageModal(item = null, duplicate = false) {
    const form = $("#package-form");
    form.reset();
    $("#package-id").value = duplicate ? "" : item?.id || "";
    $("#package-modal-title").textContent = item && !duplicate ? "Edit paket" : duplicate ? "Duplikasi paket" : "Buat paket baru";
    $("#package-name").value = item ? `${item.name}${duplicate ? " Copy" : ""}` : "";
    $("#package-slug").value = item ? `${item.slug}${duplicate ? "-copy" : ""}` : "";
    $("#package-slug").disabled = Boolean(item && !duplicate);
    $("#package-description").value = item?.description || "";
    $("#package-price").value = item?.price_idr || "";
    $("#package-hits").value = item?.included_hits || "";
    $("#package-rpm").value = item?.rate_limit_per_minute || "";
    $("#package-active").checked = item?.active ?? true;
    $("#package-highlighted").checked = item?.highlighted ?? false;
    $("#package-promo-percent").value = item?.promo_percent ?? 0;
    $("#package-promo-ends").value = item?.promo_ends_at ? toLocalDatetime(item.promo_ends_at) : "";
    $$("input[name='package-product']").forEach((checkbox) => {
      checkbox.checked = !item || item.products.includes(checkbox.value);
    });
    openModal("package-modal");
  }

  // ISO UTC -> nilai input datetime-local (zona waktu peramban admin).
  function toLocalDatetime(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  }

  function openRateLimitModal(item = null) {
    const form = $("#rate-limit-form");
    form.reset();
    $("#rate-limit-id").value = item?.id || "";
    $("#rate-limit-modal-title").textContent = item ? "Edit kebijakan rate limit" : "Tambah kebijakan rate limit";
    $("#rate-limit-name").value = item?.name || "";
    $("#rate-limit-scope").value = item?.scope || "global";
    $("#rate-limit-scope").disabled = Boolean(item);
    $("#rate-limit-target").value = item?.target || "";
    $("#rate-limit-rpm").value = item?.requests_per_minute || 120;
    $("#rate-limit-burst").value = item?.burst || 30;
    $("#rate-limit-concurrency").value = item?.concurrency_limit || 12;
    $("#rate-limit-active").checked = item?.active ?? true;
    openModal("rate-limit-modal");
  }

  function openApiKeyModal() {
    $("#api-key-form").reset();
    $$("input[name='api-key-scope']").forEach((checkbox) => {
      checkbox.checked = checkbox.value !== "validate:*";
    });
    openModal("api-key-modal");
  }

  // Kode e-wallet member (urutan sama dengan katalog backend) untuk panel
  // mapping kode pihak ketiga. Hanya endpoint e-wallet mode Generic yang
  // memakai mapping ini; Tukangcek/Cutiezy memakai mapping bawaannya.
  const EWALLET_SERVICE_CODES = [["dana", "DANA"], ["gopay", "GoPay"], ["ovo", "OVO"], ["linkaja", "LinkAja"], ["shopeepay", "ShopeePay"], ["astrapay", "AstraPay"], ["gopay_driver", "GoPay Driver"], ["isaku", "i.Saku"], ["kaspro", "KasPro"]];

  function serviceMappingSummary(endpoint) {
    const mapping = endpoint.service_code_mapping || {};
    const changed = EWALLET_SERVICE_CODES.filter(([code]) => mapping[code] && mapping[code] !== code).map(([code]) => `${code}→${mapping[code]}`);
    return changed.length ? changed.join(" · ") : "—";
  }

  // Panel mapping hanya tampil untuk e-wallet mode Generic. `saved` (dari
  // endpoint yang dibuka) selalu menang; tanpa itu, input kosong diisi
  // kode member sendiri (identitas = dikirim apa adanya) dan input yang
  // sudah diketik tidak pernah ditimpa.
  function renderServiceMapping(product, mode, saved) {
    const panel = $("#service-mapping-panel");
    if (!panel) return;
    const visible = product === "ewallet" && mode === "generic";
    panel.hidden = !visible;
    if (!visible) return;
    for (const [code] of EWALLET_SERVICE_CODES) {
      const input = $(`#service-code-${code}`);
      if (!input) continue;
      if (saved && Object.prototype.hasOwnProperty.call(saved, code)) input.value = saved[code] || code;
      else if (!input.value) input.value = code;
    }
  }

  function collectServiceMapping(product, mode) {
    if (product !== "ewallet" || mode !== "generic") return {};
    const mapping = {};
    for (const [code] of EWALLET_SERVICE_CODES) {
      const input = $(`#service-code-${code}`);
      const value = input ? input.value.trim() : "";
      if (value) mapping[code] = value;
    }
    return mapping;
  }

  function bankMappingSummary(endpoint) {
    const mapping = endpoint.service_code_mapping || {};
    const changed = Object.keys(mapping).sort().filter((code) => mapping[code] && mapping[code] !== code).map((code) => `${code}→${mapping[code]}`);
    return changed.length ? changed.join(" · ") : "—";
  }

  // Bank mapping uses one row per overridden code (111 inputs would bury
  // the form); rows only exist for codes that differ from the member code.
  function addBankMappingRow(code, value) {
    const container = $("#bank-mapping-rows");
    if (!container) return false;
    const used = new Set($$(".bank-mapping-row").map((row) => row.querySelector(".bank-mapping-code").value));
    const options = (state.banks || []).filter((bank) => !used.has(bank.code_bank));
    if (!options.length) return false;
    const row = document.createElement("div");
    row.className = "bank-mapping-row form-grid mapping-grid";
    row.innerHTML = `<label>Kode member<select class="bank-mapping-code">${options.map((bank) => `<option value="${escapeHtml(bank.code_bank)}">${escapeHtml(bank.code_bank)} · ${escapeHtml(bank.name_bank)}</option>`).join("")}</select></label><label>Kode provider<input class="bank-mapping-value" maxlength="100" placeholder="Mis. BCA" /></label><button class="table-action danger" type="button" data-bank-row-remove>Hapus</button>`;
    container.appendChild(row);
    const select = row.querySelector(".bank-mapping-code");
    if (code && options.some((bank) => bank.code_bank === code)) select.value = code;
    row.querySelector(".bank-mapping-value").value = value || "";
    return true;
  }

  function renderBankMapping(product, mode, saved) {
    const panel = $("#bank-mapping-panel");
    if (!panel) return;
    const visible = product === "bank_account" && mode === "generic";
    panel.hidden = !visible;
    if (!visible) return;
    const container = $("#bank-mapping-rows");
    container.innerHTML = "";
    if (saved) {
      Object.keys(saved).sort().forEach((code) => {
        if (saved[code]) addBankMappingRow(code, saved[code]);
      });
    }
  }

  function collectBankMapping(product, mode) {
    if (product !== "bank_account" || mode !== "generic") return {};
    const mapping = {};
    $$(".bank-mapping-row").forEach((row) => {
      const code = row.querySelector(".bank-mapping-code").value;
      const value = row.querySelector(".bank-mapping-value").value.trim();
      if (code && value && !Object.prototype.hasOwnProperty.call(mapping, code)) mapping[code] = value;
    });
    return mapping;
  }

  function renderHttpFields(mode) {
    const panel = $("#provider-http-fields");
    if (panel) panel.hidden = mode !== "generic";
  }

  // Pure builder (no DOM): the exact request a provider endpoint would send,
  // for the modal preview. Kept dependency-free so it can be unit-tested
  // from node by extracting this function from app.js.
  function buildProviderPreviewText(config) {
    const translated = (code) => {
      if (code === null || code === undefined || code === "") return code;
      const mapped = config.mapping ? config.mapping[code] : undefined;
      return mapped && mapped.trim() !== "" ? mapped : code;
    };
    const headerLine = config.authHeader
      ? `Header: ${config.authHeader}: •••• (tersimpan)`
      : "Tanpa header auth (header kosong — tidak ada header dikirim)";
    // The bullet placeholder is a redaction marker, not a real value, so it
    // stays readable instead of percent-encoding into %E2%80%A2 sequences.
    const query = (pairs) => pairs.map(([key, value]) => `${encodeURIComponent(key)}=${value === "••••••" ? value : encodeURIComponent(value)}`).join("&");
    if (config.mode === "cutiezy") {
      const codeKey = config.product === "ewallet" ? "service" : "code";
      const pairs = [];
      if (config.product !== "whatsapp") pairs.push([codeKey, translated(config.sampleCode)]);
      pairs.push(["user_id", config.sampleTarget]);
      pairs.push(["apikey", "••••••"]);
      return `GET ${config.baseUrl}?${query(pairs)}\nKunci lewat query (konvensi Cutiezy); header diabaikan.`;
    }
    if (config.mode === "tukangcek") {
      const body = config.product === "whatsapp"
        ? { target: config.sampleTarget }
        : { type: config.product === "ewallet" ? "ewallet" : "bank", target: config.sampleTarget, id: `${translated(config.sampleCode)} (diterjemahkan tabel bawaan Tukangcek)` };
      return `POST ${config.baseUrl}\n${headerLine}\nBody: ${JSON.stringify(body, null, 2)}`;
    }
    if (config.method === "GET") {
      const pairs = [];
      if (config.product !== "whatsapp") pairs.push([config.codeParam, translated(config.sampleCode)]);
      pairs.push([config.numberParam, config.sampleTarget]);
      if (config.keyParam) pairs.push([config.keyParam, "••••••"]);
      return `GET ${config.baseUrl}?${query(pairs)}\n${headerLine}`;
    }
    const body = {
      product: config.product,
      target: config.sampleTarget,
      provider_hint: config.product === "whatsapp" ? null : translated(config.sampleCode),
      request_reference: "<uuid dibuat saat kirim>",
    };
    return `POST ${config.baseUrl}\n${headerLine}\nBody: ${JSON.stringify(body, null, 2)}`;
  }

  function renderProviderPreview() {
    const panel = $("#provider-preview");
    if (!panel) return;
    const product = $("#provider-product").value;
    const mode = $("#provider-request-mode").value;
    const mapping = product === "ewallet"
      ? collectServiceMapping(product, mode)
      : collectBankMapping(product, mode);
    panel.textContent = buildProviderPreviewText({
      product,
      mode,
      method: ($("#provider-http-method").value || "POST").toUpperCase(),
      baseUrl: $("#provider-base-url").value.trim(),
      authHeader: $("#provider-auth-header").value.trim(),
      codeParam: $("#provider-code-param").value.trim() || "code",
      numberParam: $("#provider-number-param").value.trim() || "target",
      keyParam: $("#provider-key-param").value.trim() || null,
      mapping,
      sampleTarget: $("#provider-sample-target").value.trim(),
      sampleCode: $("#provider-sample-code").value.trim(),
    });
    const codeLabel = $("#provider-sample-code-label");
    if (codeLabel) codeLabel.hidden = product === "whatsapp";
  }

  function mappingValues(value) {
    return Array.isArray(value) ? value.join(", ") : "";
  }

  function nullablePath(selector, value) {
    $(selector).value = value || "";
  }

  function applyProviderMapping(product, mapping) {
    const selected = mapping || defaultProviderMapping(product);
    $("#mapping-status-path").value = selected.status_path || "status";
    $("#mapping-valid-values").value = mappingValues(selected.valid_values);
    $("#mapping-invalid-values").value = mappingValues(selected.invalid_values);
    $("#mapping-not-found-values").value = mappingValues(selected.not_found_values);
    $("#mapping-pending-values").value = mappingValues(selected.pending_values);
    nullablePath("#mapping-message-path", selected.message_path);
    nullablePath("#mapping-account-name-path", selected.account_name_path);
    nullablePath("#mapping-provider-path", selected.provider_path);
    nullablePath("#mapping-registered-path", selected.registered_path);
    nullablePath("#mapping-reference-path", selected.reference_path);

    const isBank = product === "bank_account";
    const isEwallet = product === "ewallet";
    $$(".mapping-bank-field").forEach((element) => { element.hidden = product === "whatsapp"; });
    $$(".mapping-provider-field, .mapping-reference-field").forEach((element) => { element.hidden = false; });
    $$(".mapping-registration-field").forEach((element) => { element.hidden = isBank; });
    $("#mapping-product-note").textContent = isBank
      ? "Rekening: petakan status dan nama pemilik rekening."
      : isEwallet
        ? "E-wallet: petakan status, nama pemilik akun, dan status terdaftar."
        : "WhatsApp: hanya status terdaftar/tidak — tanpa nama.";
    $("#mapping-privacy-note").textContent = isEwallet
      ? "Nama akun e-wallet ditampilkan ke member apa adanya dari provider (umumnya sudah tersamar). Hanya field yang dipetakan yang masuk ke respons Rajacek."
      : "Hanya field yang dipetakan akan masuk ke respons normal Rajacek; payload mentah tidak diteruskan.";
  }

  function splitMappingValues(selector) {
    return $(selector).value.split(",").map((value) => value.trim()).filter(Boolean);
  }

  function optionalMappingPath(selector) {
    return $(selector).value.trim() || null;
  }

  // Duplikat membuka modal tambah dengan semua field terisi kecuali id dan
  // kredensial: kunci lama tidak pernah dikembalikan API, jadi admin wajib
  // mengisi kunci baru untuk salinannya (backend menolak create tanpa kunci).
  function duplicateProvider(endpoint) {
    const copy = { ...endpoint, id: "", force_on: false, name: `${endpoint.name} (salinan)` };
    openProviderModal(copy);
    $("#provider-modal-title").textContent = `Tambah server — ${productLabel(endpoint.product)} (salinan)`;
    $("#provider-api-key").placeholder = "Wajib diisi untuk endpoint baru";
    $("#provider-api-key").focus();
  }

  function openProviderModal(endpoint, productForNew) {
    const product = endpoint ? endpoint.product : productForNew;
    $("#provider-form").reset();
    $("#provider-id").value = endpoint ? endpoint.id : "";
    $("#provider-product").value = product;
    $("#provider-name").value = endpoint ? endpoint.name : "";
    $("#provider-base-url").value = endpoint ? endpoint.base_url : "";
    $("#provider-timeout").value = endpoint ? endpoint.timeout_ms : 8000;
    $("#provider-request-mode").value = endpoint ? (endpoint.request_mode || "generic") : "generic";
    $("#provider-http-method").value = endpoint && (endpoint.http_method || "POST").toUpperCase() === "GET" ? "GET" : "POST";
    $("#provider-code-param").value = endpoint ? (endpoint.code_param || "code") : "code";
    $("#provider-number-param").value = endpoint ? (endpoint.number_param || "target") : "target";
    $("#provider-key-param").value = endpoint ? (endpoint.key_param || "") : "";
    renderHttpFields($("#provider-request-mode").value);
    $("#provider-auth-header").value = endpoint ? (endpoint.auth_header ?? "Authorization") : "Authorization";
    $("#provider-api-key").value = "";
    $("#provider-api-key").placeholder = "Kosongkan jika tidak ingin merotasi kredensial";
    $("#provider-active").checked = endpoint ? endpoint.active : true;
    $("#provider-force-on").checked = endpoint ? !!endpoint.force_on : false;
    applyProviderMapping(product, endpoint ? endpoint.response_mapping : presetMapping(product, $("#provider-request-mode").value));
    renderServiceMapping(product, $("#provider-request-mode").value, endpoint ? endpoint.service_code_mapping : null);
    renderBankMapping(product, $("#provider-request-mode").value, endpoint ? endpoint.service_code_mapping : null);
    $("#provider-sample-target").value = "1234567890";
    $("#provider-sample-code").value = product === "bank_account" ? "014" : product === "ewallet" ? "dana" : "";
    renderProviderPreview();
    $("#provider-modal-title").textContent = endpoint ? `Kelola ${endpoint.name}` : `Tambah server — ${productLabel(product)}`;
    openModal("provider-modal");
  }

  async function submitProvider(event) {
    event.preventDefault();
    const product = $("#provider-product").value;
    const credential = $("#provider-api-key").value;
    const payload = {
      name: $("#provider-name").value.trim(),
      base_url: $("#provider-base-url").value.trim(),
      api_key: credential || null,
      timeout_ms: Number($("#provider-timeout").value),
      request_mode: $("#provider-request-mode").value,
      http_method: $("#provider-http-method").value,
      code_param: $("#provider-code-param").value.trim() || "code",
      number_param: $("#provider-number-param").value.trim() || "target",
      key_param: $("#provider-key-param").value.trim() || null,
      auth_header: $("#provider-auth-header").value.trim(),
      response_mapping: {
        status_path: $("#mapping-status-path").value.trim(),
        valid_values: splitMappingValues("#mapping-valid-values"),
        invalid_values: splitMappingValues("#mapping-invalid-values"),
        not_found_values: splitMappingValues("#mapping-not-found-values"),
        pending_values: splitMappingValues("#mapping-pending-values"),
        message_path: optionalMappingPath("#mapping-message-path"),
        account_name_path: product === "whatsapp" ? null : optionalMappingPath("#mapping-account-name-path"),
        provider_path: optionalMappingPath("#mapping-provider-path"),
        registered_path: product === "bank_account" ? null : optionalMappingPath("#mapping-registered-path"),
        reference_path: optionalMappingPath("#mapping-reference-path"),
      },
      active: $("#provider-active").checked,
      force_on: $("#provider-force-on").checked,
      service_code_mapping: product === "bank_account"
        ? collectBankMapping(product, $("#provider-request-mode").value)
        : collectServiceMapping(product, $("#provider-request-mode").value),
    };
    const id = $("#provider-id").value;
    try {
      const endpoint = await api(id ? `/v1/admin/provider-endpoints/${id}` : "/v1/admin/provider-endpoints", { method: id ? "PUT" : "POST", body: { product, ...payload } });
      const index = state.providers.findIndex((item) => item.id === endpoint.id);
      if (index >= 0) state.providers[index] = endpoint;
      else state.providers.push(endpoint);
      renderProviders();
      closeModal("provider-modal");
      showToast(`Server ${endpoint.name} berhasil disimpan.`, "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  async function toggleProvider(input) {
    const id = input.dataset.id;
    const active = input.checked;
    // K29: konfirmasi SELALU — satu klik yang salah bisa mematikan
    // satu-satunya server aktif suatu produk. Server-side tetap
    // reversibel, tapi konfirmasi mencegah gangguan sesaat itu.
    const endpoint = state.providers.find((item) => item.id === id);
    const label = endpoint ? endpoint.name : "server ini";
    if (!window.confirm(active
      ? `Aktifkan server "${label}"? Server ini akan kembali menerima validasi.`
      : `Nonaktifkan server "${label}"? Validasi tidak lagi memakai server ini sampai diaktifkan lagi.`)) {
      input.checked = !active;
      return;
    }
    try {
      const endpoint = await api(`/v1/admin/provider-endpoints/${id}/active`, { method: "PATCH", body: { active } });
      const index = state.providers.findIndex((item) => item.id === endpoint.id);
      if (index >= 0) state.providers[index] = endpoint;
      renderProviders();
      showToast(`Server ${endpoint.name} ${active ? "diaktifkan" : "dinonaktifkan"}.`, "success");
    } catch (error) {
      input.checked = !active;
      handleApiError(error);
    }
  }

  async function toggleProviderForce(input) {
    const id = input.dataset.id;
    const forceOn = input.checked;
    const endpoint = state.providers.find((item) => item.id === id);
    const label = endpoint ? endpoint.name : "server ini";
    // Konfirmasi SELALU saat mengaktifkan: bypass breaker berarti tetap
    // menghantam upstream yang sedang gagal — admin harus sadar akan
    // risikonya. Mematikan paksa aman (kembali ke perilaku normal).
    if (forceOn && !window.confirm(`Paksa ON server "${label}"? Server ini akan TETAP di-admit meski circuit breaker-nya terbuka — validasi tetap menghantam upstream yang sedang gagal. Pacer & batas konkurensi tetap berlaku, dan hasil tetap dicatat ke breaker.`)) {
      input.checked = !forceOn;
      return;
    }
    try {
      const updated = await api(`/v1/admin/provider-endpoints/${id}/force-on`, { method: "PATCH", body: { force_on: forceOn } });
      const index = state.providers.findIndex((item) => item.id === updated.id);
      if (index >= 0) state.providers[index] = updated;
      renderProviders();
      showToast(`Server ${updated.name} ${forceOn ? "dipaksa ON" : "paksa ON dimatikan"} (tercatat di audit).`, "success");
    } catch (error) {
      input.checked = !forceOn;
      handleApiError(error);
    }
  }

  async function deleteProvider(id) {
    const endpoint = state.providers.find((item) => item.id === id);
    if (!endpoint || !window.confirm(`Hapus server "${endpoint.name}"? Validasi ${productLabel(endpoint.product)} tidak lagi memakai server ini.`)) return;
    try {
      await api(`/v1/admin/provider-endpoints/${id}`, { method: "DELETE" });
      state.providers = state.providers.filter((item) => item.id !== id);
      renderProviders();
      showToast(`Server ${endpoint.name} dihapus.`, "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  async function testProvider(id) {
    try {
      const result = await api(`/v1/admin/provider-endpoints/${id}/test`, { method: "POST" });
      showToast(`${result.provider}: ${result.message} (${formatNumber(result.latency_ms)} ms)`, "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  function openProductModal(product) {
    $("#product-id").value = product.id;
    $("#product-name").value = product.name;
    $("#product-description").value = product.description;
    $("#product-provider-route").value = product.provider_route;
    $("#product-active").checked = product.active;
    $("#product-modal-title").textContent = `Kelola ${product.name}`;
    openModal("product-modal");
  }

  async function submitPackage(event) {
    event.preventDefault();
    const id = $("#package-id").value;
    const products = $$('input[name="package-product"]:checked').map((input) => input.value);
    if (!products.length) {
      showToast("Pilih minimal satu produk untuk paket.", "error");
      return;
    }
    const promoPercent = Number($("#package-promo-percent").value) || 0;
    const promoEnds = $("#package-promo-ends").value;
    if (promoPercent < 0 || promoPercent > 100) {
      showToast("Potongan promo harus 0–100%.", "error");
      return;
    }
    if (promoPercent > 0 && !promoEnds) {
      showToast("Promo aktif wajib diisi tanggal berakhirnya.", "error");
      return;
    }
    const payload = {
      name: $("#package-name").value.trim(),
      description: $("#package-description").value.trim(),
      price_idr: Number($("#package-price").value),
      included_hits: Number($("#package-hits").value),
      active: $("#package-active").checked,
      highlighted: $("#package-highlighted").checked,
      products,
      rate_limit_per_minute: Number($("#package-rpm").value),
      promo_percent: promoPercent,
      promo_ends_at: promoEnds ? new Date(promoEnds).toISOString() : null,
    };
    if (!id) payload.slug = $("#package-slug").value.trim().toLowerCase();

    try {
      const packageItem = await api(id ? `/v1/admin/packages/${id}` : "/v1/admin/packages", {
        method: id ? "PATCH" : "POST",
        body: payload,
      });
      const index = state.packages.findIndex((item) => item.id === packageItem.id);
      if (index >= 0) state.packages[index] = packageItem;
      else state.packages.push(packageItem);
      renderPackages();
      closeModal("package-modal");
      showToast(`Paket ${packageItem.name} berhasil disimpan.`, "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  async function submitRateLimit(event) {
    event.preventDefault();
    const id = $("#rate-limit-id").value;
    const payload = {
      name: $("#rate-limit-name").value.trim(),
      target: $("#rate-limit-target").value.trim(),
      requests_per_minute: Number($("#rate-limit-rpm").value),
      burst: Number($("#rate-limit-burst").value),
      concurrency_limit: Number($("#rate-limit-concurrency").value),
      active: $("#rate-limit-active").checked,
    };
    if (!id) payload.scope = $("#rate-limit-scope").value;
    try {
      const policy = await api(id ? `/v1/admin/rate-limits/${id}` : "/v1/admin/rate-limits", {
        method: id ? "PATCH" : "POST",
        body: payload,
      });
      const index = state.rateLimits.findIndex((item) => item.id === policy.id);
      if (index >= 0) state.rateLimits[index] = policy;
      else state.rateLimits.push(policy);
      renderRateLimits();
      closeModal("rate-limit-modal");
      showToast(`Kebijakan ${policy.name} berhasil disimpan.`, "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  async function submitApiKey(event) {
    event.preventDefault();
    let scopes = $$('input[name="api-key-scope"]:checked').map((input) => input.value);
    if (scopes.includes("validate:*")) scopes = ["validate:*"];
    if (!scopes.length) {
      showToast("Pilih minimal satu scope untuk kunci API.", "error");
      return;
    }
    const rpm = $("#api-key-rpm").value;
    try {
      const created = await api("/v1/admin/api-keys", {
        method: "POST",
        body: {
          name: $("#api-key-name").value.trim(),
          scopes,
          rate_limit_per_minute: rpm ? Number(rpm) : null,
        },
      });
      state.apiKeys.unshift(created.key);
      renderApiKeys();
      closeModal("api-key-modal");
      $("#created-key-warning").textContent = created.warning;
      $("#created-key-value").textContent = created.plaintext_key;
      openModal("created-key-modal");
      showToast("Kunci API berhasil diterbitkan.", "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  async function submitProduct(event) {
    event.preventDefault();
    const id = $("#product-id").value;
    const payload = {
      name: $("#product-name").value.trim(),
      description: $("#product-description").value.trim(),
      provider_route: $("#product-provider-route").value.trim(),
      active: $("#product-active").checked,
    };
    try {
      const product = await api(`/v1/admin/products/${id}`, { method: "PATCH", body: payload });
      const index = state.products.findIndex((item) => item.id === product.id);
      if (index >= 0) state.products[index] = product;
      renderProducts();
      closeModal("product-modal");
      showToast(`${product.name} berhasil diperbarui.`, "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  async function deletePackage(id) {
    const item = state.packages.find((packageItem) => packageItem.id === id);
    // K27/K30: hapus paket kini tampil di panel (dulu hanya lewat API).
    // Server men-null-kan package_id kunci yang merujuk paket ini
    // dalam transaksi yang sama — kuota member TIDAK dihapus, hanya
    // provenance paketnya yang dilepas.
    if (!item || !window.confirm(`Hapus paket “${item.name}”? Kunci yang memakai paket ini dilepas dari paket (kuotanya tetap), dan paket tidak bisa dibeli lagi.`)) return;
    try {
      await api(`/v1/admin/packages/${id}`, { method: "DELETE" });
      state.packages = state.packages.filter((packageItem) => packageItem.id !== id);
      renderPackages();
      showToast(`Paket ${item.name} dihapus.`, "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  async function deleteRateLimit(id) {
    const policy = state.rateLimits.find((item) => item.id === id);
    if (!policy || !window.confirm(`Hapus kebijakan “${policy.name}”?`)) return;
    try {
      await api(`/v1/admin/rate-limits/${id}`, { method: "DELETE" });
      state.rateLimits = state.rateLimits.filter((item) => item.id !== id);
      renderRateLimits();
      showToast("Kebijakan rate limit telah dihapus.", "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  async function revokeApiKey(id) {
    const key = state.apiKeys.find((item) => item.id === id);
    if (!key) return;
    // K32: peringatan eksplisit bila kunci milik member berbayar —
    // member itu terkunci dari portal sampai kunci diregenerasi.
    const ownerNote = key.owner_email
      ? ` Ini kunci member ${key.owner_email} — member tersebut tidak bisa memakai portal sampai kuncinya diregenerasi.`
      : key.member_id
        ? ` Ini kunci member — member tersebut tidak bisa memakai portal sampai kuncinya diregenerasi.`
        : "";
    if (!window.confirm(`Cabut akses untuk kunci “${key.name}”?${ownerNote}`)) return;
    try {
      await api(`/v1/admin/api-keys/${id}`, { method: "DELETE" });
      const index = state.apiKeys.findIndex((item) => item.id === id);
      if (index >= 0) state.apiKeys[index].status = "revoked";
      renderApiKeys();
      showToast("Kunci API berhasil dicabut.", "success");
    } catch (error) {
      handleApiError(error);
    }
  }

  async function initialize() {
    setupEventListeners();
    // BESAR-2 (sisi panel): konsumsi ?auth= di awal — URL dibersihkan
    // di sini juga bila sesi ternyata sah; pesan hanya ditampilkan
    // bila akhirnya modal login yang tampil (lihat bawah).
    const authCallbackText = consumeAuthCallbackParam();
    // K28: bedakan kegagalan SESI dari kegagalan DATA. loadDashboard
    // kini menelan kegagalan data sendiri (toast + shell + catatan),
    // jadi yang sampai ke catch ini hanya: sesi tak valid (401 →
    // login), atau pemeriksaan sesi sendiri yang gagal sebelum shell
    // sempat tampil (tetap login — shell tak boleh tampil tanpa sesi
    // terverifikasi). Kegagalan data SETELAH sesi terverifikasi tidak
    // pernah memanggil showLoginOnly lagi. 403 (BESAR-4): sesi sah
    // yang ditolak perannya — tetap di shell bila shell sudah tampil;
    // cabang pra-verifikasi di bawah hanya layar awal (shell belum
    // pernah tampil, dan endpoint sesi sendiri mengembalikan 200,
    // bukan 403 — jadi cabang itu defensif, bukan tendangan sesi).
    let sessionVerified = false;
    try {
      const session = await refreshSession();
      // The gate must check the role, not just authentication (audit
      // 2026-10-25, A3): a member JWT in the same cookie jar must not
      // reveal the admin shell, even though the server still 401s data.
      // Ini gerbang payload sesi (authenticated/role), BUKAN respons
      // HTTP 403 — showLoginOnly di sini bukan tendangan 403.
      if (!session.authenticated || session.role !== "admin") {
        showLoginOnly();
        showAuthCallbackMessage(authCallbackText);
        return;
      }
      showAdmin();
      sessionVerified = true;
      await loadDashboard();
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        showLoginOnly();
        showAuthCallbackMessage(authCallbackText);
        return;
      }
      if (error instanceof ApiError && error.status === 403) {
        showToast("Anda tidak memiliki akses untuk aksi ini.", "error");
        if (sessionVerified) return;
        showLoginOnly();
        showAuthCallbackMessage(authCallbackText);
        return;
      }
      if (sessionVerified) {
        // Sesi valid, data gagal: tetap di shell, jangan ke login.
        showToast("Gagal memuat data dashboard. Coba muat ulang.", "error");
        return;
      }
      showToast("Gagal memeriksa sesi. Silakan login.", "error");
      showLoginOnly();
      showAuthCallbackMessage(authCallbackText);
    }
  }

  function setupEventListeners() {
    $$("[data-view-target]").forEach((element) => {
      if (element.tagName === "A") return;
      element.addEventListener("click", () => setActiveView(element.dataset.viewTarget));
    });

    $("#menu-button").addEventListener("click", () => document.body.classList.toggle("menu-open"));
    $("#sidebar-backdrop")?.addEventListener("click", () => document.body.classList.remove("menu-open"));
    $("#modal-backdrop").addEventListener("click", closeAllModals);
    $$("[data-close-modal]").forEach((button) => button.addEventListener("click", () => closeAllModals()));
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeAllModals();
      if (event.key === "Escape") document.body.classList.remove("menu-open");
    });

    $("#guard-form")?.addEventListener("submit", submitGuard);
    $("#rate-default-form")?.addEventListener("submit", submitRateDefault);
    $("#history-filter")?.addEventListener("submit", (event) => {
      event.preventDefault();
      state.history.offset = 0;
      loadHistory().catch(handleApiError);
    });
    $("#history-prev")?.addEventListener("click", () => {
      state.history.offset = Math.max(0, state.history.offset - state.history.limit);
      loadHistory().catch(handleApiError);
    });
    $("#history-next")?.addEventListener("click", () => {
      state.history.offset += state.history.limit;
      loadHistory().catch(handleApiError);
    });
    $("#refresh-members")?.addEventListener("click", () => loadMembers().catch(handleApiError));
    // Tab Trial/Umum: hanya filter tampilan (tanpa muat ulang dari
    // server); kombinasi dengan filter q/status/tanggal yang sudah
    // diterapkan saat loadMembers.
    $$(".member-tab").forEach((button) => {
      button.addEventListener("click", () => {
        state.membersTab = button.dataset.memberTab || "all";
        $$(".member-tab").forEach((other) => {
          const active = other === button;
          other.classList.toggle("is-active", active);
          other.setAttribute("aria-selected", active ? "true" : "false");
        });
        renderMembers();
      });
    });
    $("#refresh-orders")?.addEventListener("click", () => loadOrders().catch(handleApiError));
    $("#refresh-admins")?.addEventListener("click", () => loadAdminAccounts().catch(handleApiError));
    $("#admins-add-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const email = $("#admins-add-email").value.trim();
      const role = $("#admins-add-role").value;
      try {
        await api("/v1/admin/admins", { method: "POST", body: { email, role } });
        showToast("Admin ditambahkan.", "success");
        $("#admins-add-form").reset();
        await loadAdminAccounts();
      } catch (error) { handleApiError(error); }
    });
    $("#members-filter")?.addEventListener("submit", (event) => {
      event.preventDefault();
      loadMembers().catch(handleApiError);
    });
    $("#orders-filter")?.addEventListener("submit", (event) => {
      event.preventDefault();
      state.ordersPage.offset = 0;
      loadOrders().catch(handleApiError);
    });
    $("#export-orders")?.addEventListener("click", () => downloadAdminExport("orders", exportOrdersParams()).catch(handleApiError));
    $("#export-members")?.addEventListener("click", () => downloadAdminExport("members", exportMembersParams()).catch(handleApiError));
    $("#export-history")?.addEventListener("click", () => downloadAdminExport("usage", exportHistoryParams()).catch(handleApiError));
    $("#orders-status-filter")?.addEventListener("change", () => {
      state.ordersPage.offset = 0;
      loadOrders().catch(handleApiError);
    });
    $("#orders-apply-filter")?.addEventListener("click", () => {
      state.ordersPage.offset = 0;
      loadOrders().catch(handleApiError);
    });
    $("#orders-prev")?.addEventListener("click", () => {
      state.ordersPage.offset = Math.max(0, state.ordersPage.offset - state.ordersPage.limit);
      loadOrders().catch(handleApiError);
    });
    $("#orders-next")?.addEventListener("click", () => {
      state.ordersPage.offset += state.ordersPage.limit;
      loadOrders().catch(handleApiError);
    });
    $("#order-detail-close")?.addEventListener("click", () => { $("#order-detail").hidden = true; });
    $("#qris-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const sourceId = $("#qris-source-id").value.trim();
      const body = {
        enabled: $("#qris-enabled").checked,
        expiry_minutes: Number($("#qris-expiry").value),
        valid_days: Number($("#qris-valid-days").value),
        source_id: sourceId === "" ? null : Number(sourceId),
        api_key: $("#qris-api-key").value,
        webhook_secret: $("#qris-webhook-secret").value,
      };
      try {
        await api("/v1/admin/qris/settings", { method: "PUT", body: JSON.stringify(body) });
        $("#qris-api-key").value = "";
        $("#qris-webhook-secret").value = "";
        await loadQrisSettings();
        showToast("Pengaturan QRIS berhasil disimpan.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#telegram-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      // Token kosong = pertahankan (kecuali checkbox hapus dicentang,
      // yang mengirim string kosong = hapus). Chat ID selalu dikirim
      // (kosong = hapus) karena field-nya menampilkan nilai saat ini.
      const body = { chat_id: $("#telegram-chat-id").value.trim() };
      if ($("#telegram-clear-token").checked) {
        body.bot_token = "";
      } else if ($("#telegram-bot-token").value.trim() !== "") {
        body.bot_token = $("#telegram-bot-token").value.trim();
      }
      try {
        await api("/v1/admin/telegram-settings", { method: "PUT", body: JSON.stringify(body) });
        $("#telegram-bot-token").value = "";
        $("#telegram-clear-token").checked = false;
        await loadTelegramSettings();
        showToast("Pengaturan Telegram berhasil disimpan.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#telegram-test")?.addEventListener("click", async () => {
      try {
        const result = await api("/v1/admin/telegram-settings/test", { method: "POST", body: "{}" });
        $("#telegram-status").textContent = result.message;
        showToast(result.message, result.sent ? "success" : "error");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#telegram-webhook-activate")?.addEventListener("click", async () => {
      try {
        await api("/v1/admin/telegram-webhook/activate", { method: "POST", body: "{}" });
        await loadTelegramSettings();
        showToast("Perintah bot diaktifkan. Kirim /stats dari Telegram.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#member-key-eye")?.addEventListener("click", async () => {
      if (!state.managedMemberId) return;
      if (memberKeyShown) {
        memberKeyShown = false;
        $("#member-key-masked").textContent = memberKeyMasked;
        $("#member-key-eye").innerHTML = EYE_SVG;
        $("#member-key-eye").title = "Lihat kunci";
        $("#member-key-copy").hidden = true;
        return;
      }
      if (!memberKeyFull) {
        try {
          // K31: reveal is POST so the CSRF origin check applies (GET
          // reveal was removed server-side).
          const data = await api(`/v1/admin/members/${state.managedMemberId}/api-key/reveal`, { method: "POST" });
          memberKeyFull = data.api_key;
        } catch (error) {
          const note = $("#member-key-note");
          note.hidden = false;
          note.textContent = error.message || "Kunci tidak dapat ditampilkan.";
          return;
        }
      }
      memberKeyShown = true;
      $("#member-key-masked").textContent = memberKeyFull;
      $("#member-key-eye").innerHTML = EYE_OFF_SVG;
      $("#member-key-eye").title = "Sembunyikan kunci";
      $("#member-key-copy").hidden = false;
      $("#member-key-note").hidden = true;
    });
    $("#member-key-copy")?.addEventListener("click", async () => {
      if (!memberKeyFull) return;
      try {
        await navigator.clipboard.writeText(memberKeyFull);
        showToast("API key tersalin.", "success");
      } catch (_) { /* clipboard tidak tersedia */ }
    });
    $("#member-manage-close")?.addEventListener("click", () => {
      $("#member-manage-panel").hidden = true;
      state.managedMemberId = null;
    });
    $("#member-detail-close")?.addEventListener("click", () => {
      $("#member-detail-panel").hidden = true;
      state.memberDetail = null;
    });
    $("#member-detail-orders-prev")?.addEventListener("click", async () => {
      if (!state.memberDetail || state.memberDetailPage.offset <= 0) return;
      state.memberDetailPage.offset = Math.max(0, state.memberDetailPage.offset - state.memberDetailPage.limit);
      try { await loadMemberDetail(state.memberDetail.member.id); } catch (error) { handleApiError(error); }
    });
    $("#member-detail-orders-next")?.addEventListener("click", async () => {
      if (!state.memberDetail || !state.memberDetail.orders_has_more) return;
      state.memberDetailPage.offset += state.memberDetailPage.limit;
      try { await loadMemberDetail(state.memberDetail.member.id); } catch (error) { handleApiError(error); }
    });
    $("#member-assign-source")?.addEventListener("change", () => {
      const manual = $("#member-assign-source").value === "manual";
      $("#member-assign-package-wrap").hidden = manual;
      $("#member-assign-hits-wrap").hidden = !manual;
    });
    $("#member-assign-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!state.managedMemberId) return;
      const manual = $("#member-assign-source").value === "manual";
      const rateRaw = $("#member-assign-rate").value.trim();
      const payload = {
        mode: $("#member-assign-mode").value,
        valid_days: Number($("#member-assign-days").value),
        rate_limit_per_minute: rateRaw ? Number(rateRaw) : null,
      };
      if (manual) {
        payload.quota_hits = Number($("#member-assign-hits").value);
        if (!payload.quota_hits) return showToast("Isi jumlah hit manual dulu.", "error");
      } else {
        payload.package_id = $("#member-assign-package").value;
        if (!payload.package_id) return showToast("Pilih paket dulu (atau muat ulang halaman).", "error");
      }
      try {
        await api(`/v1/admin/members/${state.managedMemberId}/assign-package`, { method: "POST", body: JSON.stringify(payload) });
        showToast("Paket member berhasil diterapkan.", "success");
        await loadMembers();
        openMemberManage(state.managedMemberId);
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#member-rate-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!state.managedMemberId) return;
      try {
        await api(`/v1/admin/members/${state.managedMemberId}/rate-limit`, {
          method: "POST",
          body: JSON.stringify({ rate_limit_per_minute: Number($("#member-rate-value").value) }),
        });
        showToast("Rate limit member berhasil disimpan.", "success");
        await loadMembers();
        openMemberManage(state.managedMemberId);
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#member-rate-reset")?.addEventListener("click", async () => {
      if (!state.managedMemberId) return;
      const fallback = state.rateDefault?.default_per_minute;
      if (!fallback) return showToast("Default global belum termuat — muat ulang halaman.", "error");
      try {
        await api(`/v1/admin/members/${state.managedMemberId}/rate-limit`, {
          method: "POST",
          body: JSON.stringify({ rate_limit_per_minute: fallback }),
        });
        showToast(`Rate limit member direset ke default global (${formatNumber(fallback)}/menit).`, "success");
        await loadMembers();
        openMemberManage(state.managedMemberId);
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#member-toggle-status")?.addEventListener("click", async () => {
      if (!state.managedMemberId) return;
      const member = state.members.find((entry) => entry.id === state.managedMemberId);
      if (!member) return;
      // K29: konfirmasi HANYA saat akan menonaktifkan (aksi yang
      // mengunci member + semua kuncinya); mengaktifkan boleh langsung.
      if (member.status === "active" && !window.confirm(`Nonaktifkan member ${member.email}? Member dan semua kuncinya tidak bisa dipakai sampai diaktifkan lagi.`)) return;
      try {
        await api(`/v1/admin/members/${member.id}/status`, {
          method: "POST",
          body: JSON.stringify({ active: member.status !== "active" }),
        });
        showToast(member.status === "active" ? "Member dinonaktifkan." : "Member diaktifkan.", "success");
        await loadMembers();
        openMemberManage(member.id);
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#member-regenerate")?.addEventListener("click", async () => {
      if (!state.managedMemberId) return;
      if (!window.confirm("Kunci lama member akan dicabut dan diganti kunci baru (kuota & masa aktif dipertahankan). Lanjut?")) return;
      try {
        const result = await api(`/v1/admin/members/${state.managedMemberId}/regenerate-key`, { method: "POST" });
        const note = $("#member-new-key");
        note.hidden = false;
        note.innerHTML = `Kunci baru member: <code>${escapeHtml(result.plaintext_key)}</code> — salin & kirim aman ke member. Kunci yang sama juga bisa dilihat lagi lewat icon mata di panel ini.`;
        showToast("Kunci member berhasil diregenerasi.", "success");
        await loadMembers();
        openMemberManage(state.managedMemberId);
        $("#member-new-key").hidden = false;
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#site-settings-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await api("/v1/admin/site-settings", {
          method: "PUT",
          body: JSON.stringify({
            announcement_text: $("#site-announcement-text").value,
            announcement_active: $("#site-announcement-active").checked,
            maintenance_banner_text: $("#site-maintenance-banner-text").value,
            maintenance_banner_active: $("#site-maintenance-banner-active").checked,
            maintenance_block_validations: $("#site-maintenance-block").checked,
          }),
        });
        showToast("Pengaturan situs berhasil disimpan.", "success");
        await loadSiteSettings();
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#trial-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await api("/v1/admin/trial-settings", {
          method: "PUT",
          body: JSON.stringify({
            quota_hits: Number($("#trial-quota").value),
            valid_days: Number($("#trial-days").value),
          }),
        });
        showToast("Pengaturan trial berhasil disimpan.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#quick-create-key").addEventListener("click", openApiKeyModal);
    $("#create-key-button").addEventListener("click", openApiKeyModal);
    $("#create-package-button").addEventListener("click", () => openPackageModal());
    $("#create-rate-limit-button").addEventListener("click", () => openRateLimitModal());
    $("#provider-request-mode").addEventListener("change", () => {
      renderServiceMapping($("#provider-product").value, $("#provider-request-mode").value, null);
      renderBankMapping($("#provider-product").value, $("#provider-request-mode").value, null);
      renderHttpFields($("#provider-request-mode").value);
      renderProviderPreview();
      if ($("#provider-request-mode").value === "tukangcek") {
        $("#provider-auth-header").value = "X-API-Key";
        const product = $("#provider-product").value;
        const endpoint = state.providers.find((item) => item.product === product);
        if (!endpoint?.base_url || endpoint.request_mode !== "tukangcek") {
          $("#provider-base-url").value = product === "whatsapp"
            ? "https://tukangcek.id/api/check-wa"
            : "https://tukangcek.id/api/check";
          applyProviderMapping(product, tukangcekProviderMapping(product));
        }
      }
    });
    $("#reset-provider-mapping").addEventListener("click", () => {
      applyProviderMapping($("#provider-product").value, presetMapping($("#provider-product").value, $("#provider-request-mode").value));
      showToast("Mapping dikembalikan ke kontrak default.");
    });
    $("#provider-form").addEventListener("input", renderProviderPreview);
    $("#provider-form").addEventListener("change", renderProviderPreview);
    $("#add-bank-mapping-row").addEventListener("click", () => {
      if (!(state.banks || []).length) {
        showToast("Katalog bank belum termuat, muat ulang panel.", "error");
        return;
      }
      if (!addBankMappingRow("", "")) {
        showToast("Semua bank sudah dipetakan.", "error");
        return;
      }
      renderProviderPreview();
    });
    $("#bank-mapping-rows").addEventListener("click", (event) => {
      const button = event.target.closest("[data-bank-row-remove]");
      if (!button) return;
      button.closest(".bank-mapping-row").remove();
      renderProviderPreview();
    });
    $("#provider-request-mode").addEventListener("change", () => {
      applyProviderMapping($("#provider-product").value, presetMapping($("#provider-product").value, $("#provider-request-mode").value));
    });
    $("#refresh-providers").addEventListener("click", async () => {
      try {
        state.providers = await api("/v1/admin/provider-endpoints");
        renderProviders();
        showToast("Konfigurasi provider berhasil dimuat ulang.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#refresh-analytics")?.addEventListener("click", async () => {
      try {
        await loadAnalytics();
        showToast("Analitik berhasil dimuat ulang.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#analytics-range-form")?.addEventListener("submit", (event) => {
      event.preventDefault();
      state.analyticsDays = Number($("#analytics-days").value) || 30;
      loadAnalytics().catch(handleApiError);
    });
    // Tab Analitik: hanya show/hide seksi (tanpa reload data, tanpa hash).
    // Semua seksi tetap dirender saat load; grafik batang memakai tinggi %
    // sehingga aman dirender dalam panel hidden.
    document.querySelectorAll("[data-analytics-tab]").forEach((button) => {
      button.addEventListener("click", () => {
        document.querySelectorAll("[data-analytics-tab]").forEach((other) => {
          const active = other === button;
          other.classList.toggle("is-active", active);
          other.setAttribute("aria-selected", active ? "true" : "false");
        });
        document.querySelectorAll(".analytics-tabpanel").forEach((panel) => {
          panel.hidden = panel.id !== button.getAttribute("aria-controls");
        });
      });
    });
    // Tab Pengaturan: hanya show/hide panel (tanpa reload data, tanpa
    // mengubah nilai form — panel disembunyikan, bukan dihapus dari DOM).
    document.querySelectorAll("[data-settings-tab]").forEach((button) => {
      button.addEventListener("click", () => {
        document.querySelectorAll("[data-settings-tab]").forEach((other) => {
          const active = other === button;
          other.classList.toggle("is-active", active);
          other.setAttribute("aria-selected", active ? "true" : "false");
        });
        document.querySelectorAll("#view-settings [role=\"tabpanel\"]").forEach((panel) => {
          panel.hidden = panel.id !== button.getAttribute("aria-controls");
        });
      });
    });
    $("#refresh-provider-health")?.addEventListener("click", async () => {
      try {
        await loadProviderHealth();
        await loadStreamHealth();
        await loadTrialMonitor();
        await loadDlq();
        showToast("Kesehatan rute berhasil dimuat ulang.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#refresh-trial-monitor")?.addEventListener("click", async () => {
      try {
        await loadTrialMonitor();
        showToast("Monitor trial berhasil dimuat ulang.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#refresh-overview").addEventListener("click", async () => {
      try {
        await refreshOverview();
        showToast("Ringkasan berhasil diperbarui.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#refresh-activity").addEventListener("click", async () => {
      try {
        await refreshOverview();
        await loadAdminActivity();
        showToast("Aktivitas terbaru dimuat ulang.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });
    $("#admin-activity-prev")?.addEventListener("click", () => {
      state.adminActivity.offset = Math.max(0, state.adminActivity.offset - state.adminActivity.limit);
      loadAdminActivity().catch(handleApiError);
    });
    $("#admin-activity-next")?.addEventListener("click", () => {
      state.adminActivity.offset += state.adminActivity.limit;
      loadAdminActivity().catch(handleApiError);
    });
    $("#admin-activity-filter")?.addEventListener("submit", (event) => {
      event.preventDefault();
      state.adminActivity.action = $("#admin-activity-action").value.trim();
      state.adminActivity.actor = $("#admin-activity-actor").value.trim();
      state.adminActivity.from = $("#admin-activity-from").value;
      state.adminActivity.to = $("#admin-activity-to").value;
      state.adminActivity.offset = 0;
      loadAdminActivity().catch(handleApiError);
    });

    $("#mode-banner .banner-dismiss").addEventListener("click", () => {
      $("#mode-banner").hidden = true;
    });

    $("#development-token-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const token = $("#development-token").value.trim();
      if (!token) {
        showToast("Masukkan token administrator pengembangan.", "error");
        return;
      }
      sessionStorage.setItem("rajacek:development-admin-token", token);
      try {
        const session = await refreshSession();
        if (!session.authenticated) throw new ApiError("Token administrator tidak valid.", 401, null);
        showAdmin();
        await loadDashboard();
        showToast("Akses administrator berhasil diverifikasi.", "success");
      } catch (error) {
        sessionStorage.removeItem("rajacek:development-admin-token");
        handleApiError(error);
      }
    });

    $("#local-login-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const email = $("#local-email").value.trim();
      const password = $("#local-password").value;
      if (!email || !password) {
        showToast("Masukkan email dan password akun lokal.", "error");
        return;
      }
      try {
        const session = await api("/v1/auth/local/login", { method: "POST", body: { email, password } });
        state.session = session;
        updateSessionUI();
        if (session.role !== "admin") {
          // KECIL-6 (audit login 2026-10-27): login lokal role member
          // baru saja men-set cookie sesi — jangan biarkan tertinggal
          // di browser panel. Panggil logout (server membersihkan
          // cookie sesi, termasuk varian-variannya) SEBELUM toast,
          // lalu kembali ke tampilan login. Kegagalan logout
          // diabaikan di sini: state lokal tetap dibersihkan dan
          // gerbang sesi admin menolak role member, jadi shell tidak
          // pernah tampil; cookie HttpOnly tidak bisa dihapus dari
          // JS bila request logout itu sendiri gagal jaringan.
          try {
            await api("/v1/auth/logout", { method: "POST" });
          } catch (_) {
            /* best-effort: lihat komentar di atas */
          }
          state.session = null;
          updateSessionUI();
          showLoginOnly();
          showToast("Login member berhasil. Akun member tidak dapat mengakses dashboard administrator.", "error");
          return;
        }
        showAdmin();
        await loadDashboard();
        showToast("Login administrator lokal berhasil.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });

    $("#toggle-token-visibility").addEventListener("click", () => {
      const input = $("#development-token");
      input.type = input.type === "password" ? "text" : "password";
    });

    $("#toggle-local-password").addEventListener("click", () => {
      const input = $("#local-password");
      input.type = input.type === "password" ? "text" : "password";
    });

    $("#toggle-pin-visibility").addEventListener("click", () => {
      const input = $("#pin-pin");
      input.type = input.type === "password" ? "text" : "password";
    });

    // PIN hanya angka: buang karakter non-digit saat mengetik/menempel
    // (type tetap password agar tersamar; bukan type=number supaya
    // tidak ada spinner/notasi e).
    for (const id of ["#pin-pin", "#pin-current", "#pin-new", "#pin-new-confirm"]) {
      $(id).addEventListener("input", (event) => {
        const filtered = event.target.value.replace(/\D/g, "");
        if (filtered !== event.target.value) event.target.value = filtered;
      });
    }

    // Login administrator dengan email + PIN (jalur produksi kedua di
    // samping Google). Pesan error berasal dari server dan sudah
    // generik ("Email atau PIN salah" / pesan throttle) — aman tampil.
    $("#pin-login-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const email = $("#pin-email").value.trim();
      const pin = $("#pin-pin").value;
      if (!email || !pin) {
        showToast("Masukkan email dan PIN administrator.", "error");
        return;
      }
      try {
        const session = await api("/v1/auth/admin/pin-login", { method: "POST", body: { email, pin } });
        state.session = session;
        updateSessionUI();
        if (session.role !== "admin") {
          state.session = null;
          updateSessionUI();
          showLoginOnly();
          showToast("Akun ini tidak dapat mengakses dashboard administrator.", "error");
          return;
        }
        showAdmin();
        await loadDashboard();
        await refreshPinStatus().catch(() => {});
        showToast("Login PIN administrator berhasil.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });

    $("#pin-default-banner-action").addEventListener("click", () => {
      setActiveView("settings");
      // Banner PIN harus membuka tab PIN, bukan tab default — panel PIN
      // tersembunyi di balik tab lain bila hanya view yang dialihkan.
      $("#settings-tab-btn-pin")?.click();
    });

    $("#pin-change-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const currentPin = $("#pin-current").value;
      const newPin = $("#pin-new").value;
      const confirmPin = $("#pin-new-confirm").value;
      if (!currentPin || !newPin || !confirmPin) {
        showToast("Lengkapi PIN lama, PIN baru, dan konfirmasinya.", "error");
        return;
      }
      if (newPin.length < 6 || !/^\d+$/.test(newPin)) {
        showToast("PIN baru harus berupa angka saja dan minimal 6 digit.", "error");
        return;
      }
      if (newPin !== confirmPin) {
        showToast("Konfirmasi PIN baru tidak cocok.", "error");
        return;
      }
      try {
        await api("/v1/admin/pin-change", { method: "POST", body: { current_pin: currentPin, new_pin: newPin } });
        $("#pin-change-status").textContent = "PIN berhasil diubah. Login berikutnya memakai PIN baru.";
        event.target.reset();
        await refreshPinStatus().catch(() => {});
        showToast("PIN administrator berhasil diubah.", "success");
      } catch (error) {
        handleApiError(error);
      }
    });

    $("#logout-button").addEventListener("click", async () => {
      // B5: logout now answers 200 { revoked, warning } instead of a
      // silent 204 — surface a failed server-side revoke explicitly.
      let logoutWarning = null;
      try {
        const result = await api("/v1/auth/logout", { method: "POST" });
        logoutWarning = result && result.warning ? result.warning : null;
      } catch (error) {
        if (!(error instanceof ApiError && error.status === 401)) handleApiError(error);
      }
      sessionStorage.removeItem("rajacek:development-admin-token");
      state.session = null;
      state.overview = null;
      updateSessionUI();
      showLoginOnly();
      if (logoutWarning) {
        showToast(logoutWarning, "warning");
      } else {
        showToast("Sesi telah diakhiri.", "success");
      }
    });

    $("#package-form").addEventListener("submit", submitPackage);
    $("#rate-limit-form").addEventListener("submit", submitRateLimit);
    $("#api-key-form").addEventListener("submit", submitApiKey);
    $("#product-form").addEventListener("submit", submitProduct);
    $("#provider-form").addEventListener("submit", submitProvider);
    $("#provider-tester-form").addEventListener("submit", submitProviderTester);
    $("#tester-product").addEventListener("change", updateTesterFields);
    $(".tester-tabs").addEventListener("click", (event) => {
      const tab = event.target.closest("[data-tester-tab]");
      if (tab) selectTesterTab(tab.dataset.testerTab);
    });
    $(".tester-tabs").addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      const tabs = $$("[data-tester-tab]");
      const index = tabs.indexOf(document.activeElement);
      if (index < 0) return;
      event.preventDefault();
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1
        : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      selectTesterTab(tabs[next].dataset.testerTab, true);
    });
    updateTesterFields();

    $("#copy-created-key").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText($("#created-key-value").textContent);
        $("#copy-created-key").textContent = "Tersalin";
        showToast("Kunci API disalin ke clipboard.", "success");
        window.setTimeout(() => { $("#copy-created-key").textContent = "Salin"; }, 1600);
      } catch {
        showToast("Tidak dapat menyalin otomatis. Salin kunci secara manual.", "error");
      }
    });

    $$("[data-toast]").forEach((button) => button.addEventListener("click", () => showToast(button.dataset.toast)));

    document.addEventListener("click", (event) => {
      const actionElement = event.target.closest("[data-action]");
      if (!actionElement) return;
      const { action, id } = actionElement.dataset;
      if (action === "edit-package") {
        const item = state.packages.find((packageItem) => packageItem.id === id);
        if (item) openPackageModal(item);
      }
      if (action === "duplicate-package") {
        const item = state.packages.find((packageItem) => packageItem.id === id);
        if (item) openPackageModal(item, true);
      }
      if (action === "delete-package") deletePackage(id);
      if (action === "admin-toggle") toggleAdminAccount(id, actionElement.dataset.active !== "1");
      if (action === "admin-delete") deleteAdminAccount(id);
      if (action === "edit-rate-limit") {
        const item = state.rateLimits.find((policy) => policy.id === id);
        if (item) openRateLimitModal(item);
      }
      if (action === "delete-rate-limit") deleteRateLimit(id);
      if (action === "revoke-api-key") revokeApiKey(id);
      if (action === "edit-product") {
        const item = state.products.find((product) => product.id === id);
        if (item) openProductModal(item);
      }
      if (action === "edit-provider") {
        const endpoint = state.providers.find((item) => item.id === id);
        if (endpoint) openProviderModal(endpoint);
      }
      if (action === "duplicate-provider") {
        const endpoint = state.providers.find((item) => item.id === id);
        if (endpoint) duplicateProvider(endpoint);
      }
      if (action === "add-provider") openProviderModal(null, id);
      if (action === "delete-provider") deleteProvider(id);
      if (action === "toggle-provider") toggleProvider(actionElement);
      if (action === "toggle-provider-force") toggleProviderForce(actionElement);
      if (action === "health-toggle-provider") toggleHealthProvider(id);
      if (action === "history-detail") openHistoryDetail(id);
      if (action === "dlq-replay") replayDlq(id);
      if (action === "dlq-replay-all") replayAllDlq();
      if (action === "toggle-provider-detail") {
        const row = actionElement.closest(".ep-row");
        const detail = row ? row.querySelector(".ep-detail") : null;
        if (detail) {
          detail.hidden = !detail.hidden;
          actionElement.textContent = detail.hidden ? "Detail ▾" : "Detail ▴";
          actionElement.setAttribute("aria-expanded", String(!detail.hidden));
        }
      }
      if (action === "test-provider") testProvider(id);
    });
  }

  document.addEventListener("DOMContentLoaded", initialize);
})();
