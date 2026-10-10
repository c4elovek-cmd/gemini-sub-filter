/**
 * Cloudflare Pages Function — https://c4elovek.online/workgemini
 *
 * Отдаёт отфильтрованную подписку в двух форматах, выбирая по User-Agent:
 *   clash/mihomo/verge/stash/Happ -> Clash-конфиг (YAML)
 *   v2rayNG/NekoBox/Streisand     -> base64 со ссылками vless
 *
 * Доступ. Человеку пароль вводится один раз на странице /gemini/ — тогда его
 * IP запоминается, и обычная ссылка /workgemini начинает работать.
 * Пароль можно передать и напрямую:
 *   1. в пути      — /workgemini/<пароль>   (понимают все VPN-клиенты)
 *   2. в запросе   — /workgemini?key=<пароль>
 *   3. Basic Auth  — для браузера, с окном ввода
 *
 * Сам пароль берётся из переменной окружения PASSWORD, а не из кода:
 * репозиторий сайта публичный, и всё, что в нём лежит, видно всем.
 *
 * Хранилище IP — KV-биндинг LINKS (он уже есть в проекте), ключи с префиксом wg_.
 */

const KV_PREFIX = "wg_";
// Сколько помним IP, введший пароль. Раньше было 90 дней — слишком много:
// любой, кто попал на этот IP (общий Wi-Fi, гостиница, NAT оператора,
// сосед по роутеру), забирал подписку без пароля три месяца. Недели хватает,
// чтобы планшет и компьютер не переспрашивали пароль каждый день.
const IP_TTL_SECONDS = 14 * 24 * 3600;
const FAIL_TTL_SECONDS = 600;          // окно счётчика неудач
const MAX_FAILS = 10;

// Журнал доступа: без него утечку подписки невозможно заметить.
const LOG_KEY = KV_PREFIX + "accesslog";
const LOG_MAX = 200;
const LOG_TTL_SECONDS = 30 * 24 * 3600;

async function accessLog(env, record) {
  try {
    if (!env || !env.LINKS) return;
    const prev = await env.LINKS.get(LOG_KEY, "text");
    const list = prev ? JSON.parse(prev) : [];
    list.push({ at: new Date().toISOString(), ...record });
    await env.LINKS.put(LOG_KEY, JSON.stringify(list.slice(-LOG_MAX)), {
      expirationTtl: LOG_TTL_SECONDS,
    });
  } catch {
    // Журнал не должен ломать выдачу подписки.
  }
}

// --- пароль ---------------------------------------------------------------

/**
 * Пароль берётся ТОЛЬКО из переменной окружения PASSWORD в настройках Pages.
 *
 * Держать его в коде нельзя: репозиторий сайта хоть и приватный, но пароль
 * в коде — это пароль на видном месте. Если переменная не задана, доступ не
 * выдаётся вовсе: лучше закрыто, чем открыто с чужим паролем.
 */
function resolvePassword(env) {
  const fromEnv = env && env.PASSWORD;
  if (typeof fromEnv === "string" && fromEnv.length >= 4) return fromEnv;
  return null;
}

// --- вспомогательное ------------------------------------------------------

/** Реальный IP посетителя. */
function clientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    (request.headers.get("X-Forwarded-For") || "").split(",")[0].trim() ||
    "0.0.0.0"
  );
}

function ipKey(ip) {
  return KV_PREFIX + "ip_" + ip;
}

function failKey(ip) {
  return KV_PREFIX + "fail_" + ip;
}

async function isKnownIp(env, ip) {
  if (!env || !env.LINKS) return false;
  try {
    return (await env.LINKS.get(ipKey(ip))) !== null;
  } catch {
    return false;
  }
}

async function readFails(env, ip) {
  if (!env || !env.LINKS) return 0;
  try {
    const raw = await env.LINKS.get(failKey(ip));
    const n = parseInt(raw || "0", 10);
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
}

/** Разбирает "user:pass" из заголовка Authorization. */
function basicPassword(request) {
  const header = request.headers.get("Authorization") || "";
  if (!header.toLowerCase().startsWith("basic ")) return null;
  try {
    const decoded = atob(header.slice(6).trim());
    return decoded.slice(decoded.indexOf(":") + 1);
  } catch {
    return null;
  }
}

/** Проверяет пароль из пути, из query или из Basic Auth. */
function hasKey(request, url, segments, password) {
  // В пути пароль всегда первый сегмент: /workgemini/<пароль>[/<действие>]
  if (segments.length && segments[0] === password) return true;
  if (url.searchParams.get("key") === password) return true;
  if (basicPassword(request) === password) return true;
  return false;
}

// --- разбор ссылки --------------------------------------------------------

function parseQuery(qs) {
  const out = {};
  for (const part of (qs || "").split("&")) {
    if (!part) continue;
    const i = part.indexOf("=");
    const k = i < 0 ? part : part.slice(0, i);
    const v = i < 0 ? "" : part.slice(i + 1);
    try {
      out[decodeURIComponent(k)] = decodeURIComponent(v.replace(/\+/g, " "));
    } catch {
      out[k] = v;
    }
  }
  return out;
}

function parseVless(link) {
  const rest = link.slice("vless://".length);
  const hashAt = rest.indexOf("#");
  const name = hashAt >= 0 ? decodeURIComponent(rest.slice(hashAt + 1)) : "";
  const head = hashAt >= 0 ? rest.slice(0, hashAt) : rest;

  const qAt = head.indexOf("?");
  const base = qAt >= 0 ? head.slice(0, qAt) : head;
  const params = qAt >= 0 ? parseQuery(head.slice(qAt + 1)) : {};

  const at = base.lastIndexOf("@");
  if (at < 0) return null;
  const uuid = base.slice(0, at);
  const hostPort = base.slice(at + 1);

  const colon = hostPort.lastIndexOf(":");
  const server = colon > 0 ? hostPort.slice(0, colon) : hostPort;
  const port = colon > 0 ? parseInt(hostPort.slice(colon + 1), 10) : 443;
  if (!server || !uuid || !Number.isFinite(port)) return null;

  return {
    name: name || `${server}:${port}`,
    type: "vless",
    server,
    port,
    uuid,
    network: (params.type || params.network || "tcp").toLowerCase(),
    security: (params.security || "none").toLowerCase(),
    sni: params.sni || params.host || "",
    fingerprint: params.fp || "chrome",
    publicKey: params.pbk || "",
    shortId: params.sid || "",
    path: params.path || "",
    host: params.host || "",
    serviceName: params.serviceName || "",
    flow: params.flow || "",
  };
}

function parseLink(line) {
  const link = line.trim();
  if (!link.startsWith("vless://")) return null;
  try {
    return parseVless(link);
  } catch {
    return null;
  }
}

// --- сборка Clash-конфига -------------------------------------------------

function toProxy(s) {
  const p = {
    name: s.name,
    type: "vless",
    server: s.server,
    port: s.port,
    uuid: s.uuid,
    udp: true,
  };

  let network = s.network;
  if (network === "raw") network = "tcp";
  if (network === "h2") network = "http";
  p.network = network;

  if (s.security === "reality") {
    p.tls = true;
    p["client-fingerprint"] = s.fingerprint;
    p["reality-opts"] = { "public-key": s.publicKey, "short-id": s.shortId };
    if (s.sni) p.servername = s.sni;
  } else if (s.security === "tls") {
    p.tls = true;
    if (s.sni) p.servername = s.sni;
    if (s.fingerprint) p["client-fingerprint"] = s.fingerprint;
  } else {
    p.tls = false;
  }

  if (s.flow) p.flow = s.flow;

  if (network === "ws") {
    p["ws-opts"] = { path: s.path || "/" };
    if (s.host) p["ws-opts"].headers = { Host: s.host };
  } else if (network === "xhttp") {
    p["xhttp-opts"] = { path: s.path || "/" };
  } else if (network === "grpc") {
    p["grpc-opts"] = { "grpc-service-name": s.serviceName || "" };
  } else if (network === "http") {
    p["http-opts"] = {
      path: [s.path || "/"],
      headers: s.host ? { Host: [s.host] } : {},
    };
  }

  return p;
}

// --- YAML -----------------------------------------------------------------

const PLAIN_SAFE = /^[A-Za-z0-9_./@ -]+$/;

function isObj(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function yamlScalar(v) {
  if (v === true) return "true";
  if (v === false) return "false";
  if (v === null || v === undefined) return "~";
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  const s = String(v);
  if (s === "") return '""';
  if (!PLAIN_SAFE.test(s)) {
    return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n") + '"';
  }
  return s;
}

function toYaml(value, indent = 0) {
  const pad = " ".repeat(indent);

  if (Array.isArray(value)) {
    if (value.length === 0) return pad + "[]";
    const out = [];
    for (const item of value) {
      if (isObj(item)) {
        if (Object.keys(item).length === 0) {
          out.push(pad + "- {}");
          continue;
        }
        const sub = toYaml(item, indent + 2).split("\n");
        out.push(pad + "- " + sub[0].slice(indent + 2));
        for (let i = 1; i < sub.length; i++) out.push(sub[i]);
      } else {
        out.push(pad + "- " + yamlScalar(item));
      }
    }
    return out.join("\n");
  }

  if (isObj(value)) {
    const keys = Object.keys(value);
    if (keys.length === 0) return pad + "{}";
    const out = [];
    for (const k of keys) {
      const v = value[k];
      if (Array.isArray(v) || isObj(v)) {
        const body = toYaml(v, indent + 2);
        if (body.endsWith("[]") || body.endsWith("{}")) {
          out.push(pad + k + ":" + body.slice(indent + 2));
        } else {
          out.push(pad + k + ":");
          out.push(body);
        }
      } else {
        out.push(pad + k + ": " + yamlScalar(v));
      }
    }
    return out.join("\n");
  }

  return pad + yamlScalar(value);
}

function buildClash(servers) {
  const proxies = servers.map(toProxy);
  const names = proxies.map((p) => p.name);

  const config = {
    "mixed-port": 7890,
    "allow-lan": false,
    mode: "rule",
    "log-level": "warning",
    dns: {
      enable: true,
      ipv6: false,
      "enhanced-mode": "fake-ip",
      "fake-ip-range": "198.18.0.1/16",
      nameserver: ["1.1.1.1", "8.8.8.8"],
      fallback: ["tls://1.1.1.1:853"],
    },
    proxies,
    "proxy-groups": [
      {
        name: "GEMINI",
        type: "url-test",
        proxies: names,
        url: "https://www.gstatic.com/generate_204",
        interval: 300,
        tolerance: 50,
      },
      {
        name: "RETRY",
        type: "select",
        proxies: names,
      },
    ],
    rules: ["MATCH,GEMINI"],
  };

  return toYaml(config, 0);
}

function base64Of(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

/**
 * Читает данные подписки.
 *
 * Основной источник — KV (env.SUBKV): он приватный, и именно поэтому данные
 * нельзя класть в репозиторий. Cloudflare Pages раздаёт все файлы из репозитория
 * как обычную статику по их пути, поэтому workgemini.txt на сайте был виден
 * всем без пароля.
 *
 * Файлы в репозитории оставлены только как запасной вариант на случай, пока
 * KV ещё не наполнен. Как только данные лежат в KV, файлы убираются.
 */
async function loadLinks(env, url) {
  if (env && env.SUBKV) {
    try {
      const raw = await env.SUBKV.get("sub");
      if (raw) return raw;
    } catch {
      /* падаем на статику ниже */
    }
  }
  const fromFile = await readAsset(env, url, "/workgemini.txt");
  return fromFile || "";
}

async function loadMeta(env, url) {
  if (env && env.SUBKV) {
    try {
      const meta = await env.SUBKV.get("meta");
      if (meta) return meta;
    } catch {
      /* падаем на статику ниже */
    }
  }
  return await readAsset(env, url, "/workgemini.meta.json");
}

async function readAsset(env, url, path) {
  const res = await env.ASSETS.fetch(new URL(path, url));
  if (!res || res.status !== 200) return null;
  return await res.text();
}

const UA_CLASH =
  /clash|mihomo|stash|verge|flclash|sparkle|karing|meta|surfboard/i;
const UA_HAPP = /happ/i;

/** base64 из строки UTF-8: btoa умеет только латиницу, а в названии есть кириллица. */
function b64Utf8(text) {
  const bytes = new TextEncoder().encode(text);
  let out = "";
  for (const b of bytes) out += String.fromCharCode(b);
  return btoa(out);
}

function formatGb(bytes) {
  const v = Number(bytes) || 0;
  if (!v) return "0";
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let x = v;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i += 1;
  }
  return (x >= 10 || i >= 3 ? x.toFixed(0) : x.toFixed(1)).replace(".", ",") + " " + units[i];
}

/** Дата в виде 09.10.2026 по московскому времени. */
function formatDateRu(value) {
  if (!value) return "";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleDateString("ru-RU", {
    timeZone: "Europe/Moscow",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  });
}

function formatDateTimeRu(value) {
  if (!value) return "";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "";
  const date = formatDateRu(value);
  const time = d.toLocaleTimeString("ru-RU", {
    timeZone: "Europe/Moscow",
    hour: "2-digit",
    minute: "2-digit",
  });
  return `${date} ${time}`;
}

/**
 * Текст блока в карточке подписки.
 *
 * Happ читает его из заголовка announce — это обычный текст в base64.
 * Без него карточка пустая: ни трафика, ни срока, ни описания.
 * Формат тот же, что у ShareSub: несколько строк, между ними пустая.
 */
/**
 * Плашка с состоянием подписки: «📦 56 ГБ · до 14.08.2036».
 *
 * Нужна в двух местах. В карточке она приходит заголовком announce, а
 * зеркало на GitHub заголовков не умеет в принципе — там отдаётся обычный
 * статический файл. Поэтому та же плашка вписана в название верхнего пункта
 * списка: это часть содержимого, и она видна через оба адреса.
 */
function subscriptionBadge(sub) {
  if (!sub) return "";
  const used = Number(sub.traffic_used) || 0;
  const limit = Number(sub.traffic_limit) || 0;
  const parts = [];
  if (used || limit) {
    parts.push(
      limit ? `📦 ${formatGb(used)} из ${formatGb(limit)}` : `📦 ${formatGb(used)} · без лимита`
    );
  }
  if (sub.expire_at) {
    parts.push(`📅 до ${formatDateRu(sub.expire_at)}`);
  }
  return parts.join(" · ");
}

function buildAnnounce(sub, data, serverCount) {
  const lines = [];

  lines.push(`⚡ c4elovek.online · Gemini · ${serverCount} серверов`);

  const badge = subscriptionBadge(sub);
  if (badge) lines.push(badge);

  const stamp = formatDateTimeRu(data.updated_at);
  if (stamp) lines.push(`🔄 Обновлено ${stamp}`);

  lines.push("");
  lines.push("🔒 В списке только те серверы, где Gemini открывается.");

  return lines.join("\n");
}

/**
 * Заголовки, по которым клиент рисует карточку подписки: израсходованный
 * трафик, лимит, срок, название и описание.
 *
 * Subscription-Userinfo — общий для клиентов подписок формат: лимит нулём
 * означает «без ограничений», и Happ рисует на его месте бесконечность.
 * Announce понимает только Happ, зато рисует по нему блок с описанием.
 */
async function subscriptionInfoHeaders(env, url, serverCount) {
  const headers = {};
  let meta = null;
  try {
    meta = await loadMeta(env, url);
  } catch {
    return headers;
  }
  if (!meta) return headers;

  let data;
  try {
    data = JSON.parse(meta);
  } catch {
    return headers;
  }

  const sub = data.subscription || {};
  const used = Number(sub.traffic_used) || 0;
  const limit = Number(sub.traffic_limit) || 0;
  const expire = sub.expire_at
    ? Math.floor(new Date(sub.expire_at).getTime() / 1000)
    : 0;

  if (used || limit || expire) {
    headers["Subscription-Userinfo"] =
      `upload=0; download=${used}; total=${limit}; expire=${expire}`;
  }

  headers["Announce"] = `base64:${b64Utf8(buildAnnounce(sub, data, serverCount))}`;

  const title = "c4elovek.online · Gemini";
  headers["Profile-Title"] = `base64:${b64Utf8(title)}`;
  // Happ берёт название карточки из Content-Disposition: без него в списке
  // подписок видно адрес хоста вместо названия. Имя файла оставляем из
  // ASCII-символов: это поле читают без base64, и разделитель-точка там
  // превращается в мусор у клиентов, которые ждут latin-1.
  headers["Content-Disposition"] =
    'attachment; filename="c4elovek.online - Gemini"; '
    + `filename*=UTF-8''${encodeURIComponent(title)}`;

  // Обновляем раз в 6 часов: чаще нет смысла, список серверов меняется
  // раз в день, а лишние запросы только тратят трафик подписки.
  headers["Profile-Update-Interval"] = "6";

  // Поля, которые шлёт сам ShareSub. Карточка собирается из набора
  // заголовков, и без некоторых клиент может не показать её целиком,
  // поэтому набор повторяем один в один, меняя только значения.
  headers["Profile-Web-Page-Url"] = "https://c4elovek.online/gemini/";
  headers["Subscriptions-Sort-Type"] = "without";
  headers["Support-Url"] = "https://c4elovek.online/gemini/";
  return headers;
}

/** Заголовок с окном ввода пароля — только для браузеров. */
function wantsBrowser(request) {
  return (request.headers.get("Accept") || "").includes("text/html");
}

/**
 * Браузеру вместо подписки нужна страница.
 *
 * VPN-клиенты шлют в Accept "звёздочку" (всё что угодно) или не шлют его
 * вовсе, поэтому по нему их можно надёжно отличить от человека — и не
 * сломать им подписку.
 */
function prefersPage(request) {
  const ua = request.headers.get("User-Agent") || "";
  if (
    /v2ray|v2rayng|nekobox|streisand|happ|clash|mihomo|stash|verge|karing|flclash|surfboard|shadowrocket|subconverter/i.test(ua)
  ) {
    return false;
  }
  return (request.headers.get("Accept") || "").includes("text/html");
}

/**
 * Формат Happ.
 *
 * Happ не понимает Clash YAML — он ждёт собственный конфиг в духе V2Ray:
 * inbounds/outbounds плюс балансировщик. ShareSub отдаёт именно его, поэтому
 * повторяем структуру один в один, иначе клиент пишет
 * «не удалось разобрать конфигурацию».
 *
 * Отдаётся массивом из одного элемента — так же, как это делает ShareSub.
 */
function toV2RayOutbound(s, tag) {
  const user = { id: s.uuid, encryption: "none" };
  if (s.flow) user.flow = s.flow;

  const stream = { network: s.network, security: s.security };

  if (s.security === "reality") {
    stream.realitySettings = {
      serverName: s.sni || s.host || "",
      fingerprint: s.fingerprint || "chrome",
      publicKey: s.publicKey,
      // xray принимает ключ и под полем password — держим оба, как у ShareSub
      password: s.publicKey,
      shortId: s.shortId || "",
      spiderX: "/",
    };
  } else if (s.security === "tls") {
    stream.tlsSettings = {
      serverName: s.sni || s.host || "",
      fingerprint: s.fingerprint || "chrome",
      allowInsecure: false,
    };
  }

  if (s.network === "ws") {
    stream.wsSettings = { path: s.path || "/" };
    if (s.host) stream.wsSettings.headers = { Host: s.host };
  } else if (s.network === "xhttp") {
    stream.xhttpSettings = { path: s.path || "/" };
    if (s.mode) stream.xhttpSettings.mode = s.mode;
  } else if (s.network === "grpc") {
    stream.grpcSettings = {
      serviceName: s.serviceName || "",
      multiMode: (s.mode || "") === "multi",
    };
  } else if (s.network === "http") {
    stream.httpSettings = {
      path: s.path || "/",
      headers: s.host ? { Host: [s.host] } : {},
    };
  }

  return {
    tag: tag,
    protocol: "vless",
    settings: {
      vnext: [{ address: s.server, port: s.port, users: [user] }],
    },
    streamSettings: stream,
  };
}

// Общие для всех элементов куски: входные порты и заглушки выходов.
const HAP_INBOUNDS = [
  {
    tag: "socks",
    port: 10808,
    listen: "127.0.0.1",
    protocol: "socks",
    settings: { udp: true, auth: "noauth" },
    sniffing: {
      enabled: true,
      routeOnly: false,
      destOverride: ["http", "tls", "quic"],
    },
  },
  {
    tag: "http",
    port: 10809,
    listen: "127.0.0.1",
    protocol: "http",
    settings: { allowTransparent: false },
    sniffing: {
      enabled: true,
      routeOnly: false,
      destOverride: ["http", "tls", "quic"],
    },
  },
];

const HAP_DIRECT = { tag: "direct", protocol: "freedom", settings: {} };
const HAP_BLOCK = { tag: "block", protocol: "blackhole", settings: {} };

/** Короткое имя сервера для подписи в Happ. */
function serverLabel(s) {
  const raw = (s.name || "").trim();
  if (!raw) return s.server + ":" + s.port;
  // Предел выбран с запасом под плашку подписки в конце названия. Обрезать
  // надо аккуратно: раньше предел был 60, и у длинных названий провайдеров
  // срезался срок — подпись обрывалась на полуслове.
  return raw.length > 72 ? raw.slice(0, 69) + "..." : raw;
}

/**
 * Список для Happ: первый элемент — автовыбор, дальше по одному на сервер.
 *
 * Happ показывает каждый элемент массива отдельной строкой, поэтому «Автовыбор»
 * с балансировщиком и есть та самая верхняя запись, а под ней лежат все серверы.
 */
/** Домены Google: им нужно попасть в туннель всегда, даже если адрес
 *  оказался российским — правило по geoip идёт ниже и увело бы их напрямую. */
const GOOGLE_DOMAINS = [
  "domain:gemini.google.com",
  "domain:google.com",
  "domain:googleapis.com",
  "domain:gstatic.com",
  "domain:googleusercontent.com",
  "domain:google.ai",
  "domain:generativelanguage.googleapis.com",
];

/**
 * Домены российских сервисов.
 *
 * Одного geoip:ru мало: у Яндекса, ВК и маркетплейсов трафик уходит на
 * зарубежные адреса и CDN, поэтому по гео они не опознаются и уходят в
 * туннель без надобности. Домены приходится перечислять.
 */
const RU_DOMAINS = [
  "domain:yandex.ru", "domain:yandex.net", "domain:yandex.com",
  "domain:ya.ru", "domain:ya.cc",
  "domain:vk.com", "domain:vk.ru", "domain:vkcdn.ru", "domain:vkuser.net",
  "domain:userapi.com", "domain:mail.ru", "domain:inbox.ru", "domain:list.ru",
  "domain:bk.ru", "domain:rambler.ru", "domain:autorambler.ru", "domain:ro.ru",
  "domain:wildberries.ru", "domain:ozon.ru", "domain:ozon.com",
  "domain:avito.ru", "domain:avito.net", "domain:drom.ru",
  "domain:sber.ru", "domain:sberbank.ru", "domain:sberdevices.ru",
  "domain:tbank.ru", "domain:tinkoff.ru", "domain:gosuslugi.ru",
  "domain:nalog.ru", "domain:pochta.ru", "domain:russianpost.ru",
  "domain:cian.ru", "domain:drive2.ru", "domain:vc.ru", "domain:habr.com",
  "domain:pikabu.ru", "domain:rutube.ru", "domain:kinopoisk.ru",
  "domain:music.yandex.ru", "domain:ivi.ru", "domain:megogo.ru",
  "domain:livejournal.com", "domain:rg.ru", "domain:rt.com",
  "domain:tass.ru", "domain:ria.ru", "domain:kommersant.ru",
  "domain:beeline.ru", "domain:mts.ru", "domain:megafon.ru",
  "domain:tele2.ru", "domain:dom.ru", "domain:rt.ru",
];

/**
 * Порядок узлов для автовыбора: от самого быстрого к самому медленному.
 *
 * Нумерация важна. Первый узел — gemini-1 — идёт запасным в балансировщике:
 * если тот не нашёл ни одного живого, трафик уходит туда молча. Раньше это
 * был просто первый сервер в списке, то есть случайный; теперь — тот, что
 * быстрее всех отвечает на Gemini по нашей проверке.
 */
function orderByMeasuredSpeed(servers, meta) {
  let timed = new Map();
  try {
    const rows = JSON.parse(meta || "{}").servers || [];
    timed = new Map(rows.map((r) => [`${r.addr}`, Number(r.ms) || 0]));
  } catch {
    timed = new Map();
  }
  // Поле адреса в разобранном сервере называется server, а не host: с host
// ключи выходили одинаковыми у всех, сортировка не работала и запасным
// оставался первый узел в списке.
const key = (s) => `${s.server}:${s.port}`;
  return [...servers].sort((a, b) => {
    const ma = timed.get(key(a)) || Number.MAX_SAFE_INTEGER;
    const mb = timed.get(key(b)) || Number.MAX_SAFE_INTEGER;
    return ma - mb;
  });
}

function buildHapp(servers, meta, groupsOn) {
  const ranked = orderByMeasuredSpeed(servers, meta);
  const autoOutbounds = ranked.map((s, i) => toV2RayOutbound(s, "gemini-" + (i + 1)));
  const fastest = ranked.length ? "gemini-1" : "gemini-1";

  const auto = {
    // Название остаётся коротким: гигабайты и срок показывает карточка
    // подписки — их рисует клиент из заголовков ответа. Вписывать то же
    // в имя узла незачем: получается дубль и глаз цепляется не за то.
    remarks: "⚡ c4elovek.online | Автовыбор",
    dns: {
      servers: ["https://1.1.1.1/dns-query", "1.1.1.1", "8.8.8.8"],
      queryStrategy: "UseIPv4",
    },
    routing: {
      rules: [
        { type: "field", protocol: ["bittorrent"], outboundTag: "direct" },
        // Google идёт первым: он обязан попасть в туннель, а не под
        // geoip:ru, если адрес случайно окажется российским.
        { type: "field", domain: GOOGLE_DOMAINS, balancerTag: "gemini-best" },
        { type: "field", domain: RU_DOMAINS, outboundTag: "direct" },
        { type: "field", ip: ["geoip:ru", "geoip:private"], outboundTag: "direct" },
        // Сеть строкой через запятую — именно так её пишет ShareSub, и именно
        // такой вид понимает Happ. Массив здесь клиент не принимает.
        { type: "field", network: "tcp,udp", balancerTag: "gemini-best" },
      ],
      // Балансировщик обязателен: правила ссылаются на gemini-best, и без
      // этого объявления конфиг не собирается — клиент отвечает
      // «неизвестный тип контента».
      balancers: [
        {
          tag: "gemini-best",
          selector: ["gemini-"],
          fallbackTag: fastest,
          strategy: { type: "leastPing" },
        },
      ],
      domainMatcher: "hybrid",
      domainStrategy: "IPIfNonMatch",
    },
    observatory: {
      subjectSelector: ["gemini-"],
      probeUrl: "https://www.gstatic.com/generate_204",
      // 30 секунд на 134 узла — это почти четыреста проверок в сутки, и на
      // мобильном интернете они заметно съедают трафик и батарею. Список
      // серверов меняется раз в день, чаще проверять незачем.
      probeInterval: "180s",
      enableConcurrency: true,
    },
    inbounds: HAP_INBOUNDS,
    outbounds: [...autoOutbounds, HAP_DIRECT, HAP_BLOCK],
  };

  const singles = servers.map((s) => ({
    remarks: serverLabel(s),
    dns: { servers: ["1.1.1.1", "1.0.0.1"], queryStrategy: "UseIP" },
    routing: {
      rules: [{ type: "field", protocol: ["bittorrent"], outboundTag: "direct" }],
      domainMatcher: "hybrid",
      domainStrategy: "IPIfNonMatch",
    },
    inbounds: HAP_INBOUNDS,
    outbounds: [toV2RayOutbound(s, "proxy"), HAP_DIRECT, HAP_BLOCK],
  }));

  // Группы по странам появляются только когда их включили переключателем
  // на странице: по умолчанию список остаётся плоским.
  return [auto, ...(groupsOn ? buildCountryGroups(ranked, meta) : []), ...singles];
}

/**
 * Записи вида «🇩🇪 Германия · 14 серверов» — по одной на страну.
 *
 * Каждая такая запись сама является конфигом: Happ показывает каждый
 * элемент массива отдельной строкой. Внутри неё свой балансировщик, который
 * выбирает самый быстрый сервер этой страны и переключается между ними сам.
 * Поэтому «выбрал Германию» — и дальше всё работает без ручного выбора из
 * четырнадцати пунктов.
 *
 * Сами группы и их названия приходят из meta: русские названия стран знает
 * скрипт публикации, а не эта функция.
 */
function buildCountryGroups(ranked, meta) {
  let groups = [];
  let countries = new Map();
  try {
    const data = JSON.parse(meta || "{}");
    groups = data.country_groups || [];
    countries = new Map(
      (data.servers || []).map((r) => [`${r.addr}`, (r.country || "").toUpperCase()])
    );
  } catch {
    return [];
  }
  if (!groups.length) return [];

  // Тег узла в списке автовыбора: порядок ranked задаёт нумерацию.
  const tagOf = new Map();
  ranked.forEach((s, i) => tagOf.set(`${s.server}:${s.port}`, "gemini-" + (i + 1)));

  const out = [];
  for (const g of groups) {
    const tags = [];
    ranked.forEach((s, i) => {
      if (countries.get(`${s.server}:${s.port}`) === g.cc) {
        tags.push("gemini-" + (i + 1));
      }
    });
    if (tags.length < 2) continue;   // один узел — не группа, а лишняя строка

    const byTag = new Map(ranked.map((s, i) => ["gemini-" + (i + 1), s]));
    out.push({
      remarks: `${g.flag} ${g.name} · ${tags.length} серверов`,
      dns: {
        servers: ["https://1.1.1.1/dns-query", "1.1.1.1", "8.8.8.8"],
        queryStrategy: "UseIPv4",
      },
      routing: {
        rules: [
          { type: "field", protocol: ["bittorrent"], outboundTag: "direct" },
          { type: "field", domain: GOOGLE_DOMAINS, balancerTag: "best" },
          { type: "field", domain: RU_DOMAINS, outboundTag: "direct" },
          { type: "field", ip: ["geoip:ru", "geoip:private"], outboundTag: "direct" },
          { type: "field", network: "tcp,udp", balancerTag: "best" },
        ],
        balancers: [
          { tag: "best", selector: tags, fallbackTag: tags[0],
            strategy: { type: "leastPing" } },
        ],
        domainMatcher: "hybrid",
        domainStrategy: "IPIfNonMatch",
      },
      observatory: {
        subjectSelector: tags,
        probeUrl: "https://www.gstatic.com/generate_204",
        probeInterval: "180s",
        enableConcurrency: true,
      },
      inbounds: HAP_INBOUNDS,
      outbounds: [
        ...tags.map((t) => toV2RayOutbound(byTag.get(t), t)),
        HAP_DIRECT,
        HAP_BLOCK,
      ],
    });
  }
  return out;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: { "Access-Control-Allow-Origin": "*" },
    });
  }

  const password = resolvePassword(env);
  const ip = clientIp(request);

  // Путь разбиваем на сегменты: [0] — пароль, дальше — действие (например status).
  // Pages отдаёт params.path массивом, но приводим и строку — так надёжнее.
  const pathParts = (context.params && context.params.path) || [];
  const list = Array.isArray(pathParts) ? pathParts : [pathParts];
  const segments = list.flatMap((x) => String(x).split("/")).filter(Boolean);

  // Первый сегмент — это пароль, только если человек идёт по ссылке с паролем.
  // А если он уже зашёл по запомненному IP, то первый сегмент сразу действие
  // (/workgemini/status), иначе страница получила бы подписку вместо сводки.
  const byKey = segments.length > 0 && segments[0] === password;
  const action = (byKey ? segments.slice(1) : segments).join("/");

  // Человек в браузере пусть лучше попадёт на страницу, чем увидит
  // простыню base64. Клиентам подписка по-прежнему отдаётся как есть.
  if (prefersPage(request) && segments.length === 0 && !url.searchParams.get("format")) {
    return Response.redirect(new URL("/gemini/", url).toString(), 302);
  }

  const allowedByIp = await isKnownIp(env, ip);
  const allowedByKey = hasKey(request, url, segments, password);

  if (!allowedByIp && !allowedByKey) {
    const fails = await readFails(env, ip);
    if (fails >= MAX_FAILS) {
      await accessLog(env, {
        outcome: "rate-limited",
        ip,
        ua: request.headers.get("User-Agent") || "",
        fails,
      });
      return new Response(
        "Слишком много попыток. Подождите 10 минут.\n",
        {
          status: 429,
          headers: { "Content-Type": "text/plain; charset=utf-8", "Retry-After": "600" },
        }
      );
    }

    const body =
      "Доступ по паролю.\n\n" +
      "Введите пароль на странице:\n" +
      new URL("/gemini/", url).toString() + "\n";

    await accessLog(env, {
      outcome: "bad-password",
      ip,
      ua: request.headers.get("User-Agent") || "",
      url: url.pathname + url.search,
      fails: fails + 1,
    });

    return new Response(body, {
      status: 401,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        // Браузер покажет штатное окно ввода. VPN-клиенты его проигнорируют,
        // им нужен пароль прямо в ссылке — см. первую строку.
        ...(wantsBrowser(request)
          ? { "WWW-Authenticate": 'Basic realm="c4elovek.online/workgemini"' }
          : {}),
      },
    });
  }

  // --- сводка последней проверки
  if (action === "status" || url.searchParams.get("status") === "1") {
    const meta = await loadMeta(env, url);
    if (meta) {
      return new Response(meta, {
        status: 200,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-cache, no-store, must-revalidate",
        },
      });
    }
  }

  let raw = "";
  try {
    raw = await loadLinks(env, url);
  } catch {
    return next();
  }

  const links = raw.split("\n").map((l) => l.trim()).filter(Boolean);
  const servers = [];
  for (const l of links) {
    const s = parseLink(l);
    if (s) servers.push(s);
  }

  if (!servers.length) {
    return next();
  }

  let format = (url.searchParams.get("format") || "").toLowerCase();
  if (!format) {
    const ua = request.headers.get("User-Agent") || "";
    if (UA_HAPP.test(ua)) format = "happ";
    else if (UA_CLASH.test(ua)) format = "clash";
    // Остальным — обычные ссылки. base64 больше не выдаётся по умолчанию.
    else format = "links";
  }

  const base = {
    ...(await subscriptionInfoHeaders(env, url, servers.length)),
    "Access-Control-Allow-Origin": "*",
    // Ответ уходит несжатым: клиент должен получить ровно тот формат, который
    // запрашивал. Со сжатием приходило «неизвестный тип контента» — часть
    // клиентов не распаковывает тело само. Обрыв в 25 КБ, из-за которого сжатие
    // включалось, объяснялся не размером, а фильтрацией имени в сети.
    "Cache-Control": "no-transform, no-cache, no-store, must-revalidate",
    "Content-Encoding": "identity",
  };

  const reply = (body, contentType) =>
    new Response(body, { status: 200, headers: { ...base, "Content-Type": contentType } });

// Служебная выкачка для скрипта: ?gz=1 просит сжатие. Клиентам оно нельзя —
// часть из них не распаковывает тело само, а скрипту нужно: через домашний
// канал большие ответы не доезжают, в сжатом виде доходят.
const wantsGzip = url.searchParams.get("gz") === "1";

async function replyMaybeGzip(body, contentType) {
  if (!wantsGzip) return reply(body, contentType);
  try {
    const stream = new Blob([body]).stream().pipeThrough(new CompressionStream("gzip"));
    return new Response(stream, {
      status: 200,
      headers: {
        ...base,
        "Content-Type": contentType,
        "Content-Encoding": "gzip",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      },
    });
  } catch {
    return reply(body, contentType);
  }
  }

  try {
    let body;
    let contentType;
    if (format === "happ") {
      // meta нужна генератору, чтобы поставить запасным узлом самый быстрый
      // по нашей проверке, а не первый попавшийся в списке.
      const meta = await loadMeta(env, url);
      // Группы по странам — по переключателю на странице.
      let groupsOn = false;
      try {
        groupsOn = env && env.LINKS
          ? (await env.LINKS.get("wg_groups")) === "on" : false;
      } catch {
        groupsOn = false;
      }
      body = JSON.stringify(buildHapp(servers, meta, groupsOn));
      contentType = "application/json; charset=utf-8";
    } else if (format === "base64" || format === "b64") {
      // Оставлено для клиентов, которым base64 обязателен: сам Happ и
      // v2rayNG читают обычные ссылки, поэтому по умолчанию ниже именно они.
      body = base64Of(links.join("\n"));
      contentType = "text/plain; charset=utf-8";
    } else if (format === "links" || format === "") {
      // Обычные ссылки vless://, trojan:// и прочие — в том виде, в каком
      // их понимает любой клиент. Раньше здесь был base64, и в списке у клиента
      // вместо названий серверов показывалась неразборчивая полоса.
      body = links.join("\n") + "\n";
      contentType = "text/plain; charset=utf-8";
    } else {
      body = buildClash(servers);
      contentType = "text/yaml; charset=utf-8";
    }

    // Служебная выкачка для скрипта в журнал не пишем: это не выдача
    // подписки человеку, а наполнение зеркала.
    if (!wantsGzip) {
      await accessLog(env, {
        outcome: "delivered",
        ip,
        ua: request.headers.get("User-Agent") || "",
        format,
        bytes: body.length,
        servers: servers.length,
        byPassword: allowedByKey,
      });
    }

    return replyMaybeGzip(body, contentType);
  } catch {
    return next();
  }
}

export { clientIp, ipKey, failKey, KV_PREFIX, IP_TTL_SECONDS, FAIL_TTL_SECONDS };