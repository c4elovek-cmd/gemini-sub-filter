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
  return raw.length > 60 ? raw.slice(0, 57) + "..." : raw;
}

/**
 * Список для Happ: первый элемент — автовыбор, дальше по одному на сервер.
 *
 * Happ показывает каждый элемент массива отдельной строкой, поэтому «Автовыбор»
 * с балансировщиком и есть та самая верхняя запись, а под ней лежат все серверы.
 */
function buildHapp(servers) {
  const autoOutbounds = servers.map((s, i) => toV2RayOutbound(s, "gemini-" + (i + 1)));

  const auto = {
    remarks: "⚡ c4elovek.online | Автовыбор",
    dns: {
      servers: ["https://1.1.1.1/dns-query", "1.1.1.1", "8.8.8.8"],
      queryStrategy: "UseIPv4",
    },
    routing: {
      rules: [
        {
          type: "field",
          domain: [
            "domain:gemini.google.com",
            "domain:google.com",
            "domain:googleapis.com",
            "domain:gstatic.com",
            "domain:googleusercontent.com",
            "domain:google.ai",
            "domain:generativelanguage.googleapis.com",
          ],
          balancerTag: "gemini-best",
        },
        { type: "field", protocol: ["bittorrent"], outboundTag: "direct" },
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
          fallbackTag: "gemini-1",
          strategy: { type: "leastPing" },
        },
      ],
      domainMatcher: "hybrid",
      domainStrategy: "IPIfNonMatch",
    },
    observatory: {
      subjectSelector: ["gemini-"],
      probeUrl: "https://www.gstatic.com/generate_204",
      probeInterval: "30s",
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

  return [auto, ...singles];
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
    else format = "base64";
  }

  const base = {
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
      body = JSON.stringify(buildHapp(servers));
      contentType = "application/json; charset=utf-8";
    } else if (format === "base64" || format === "b64") {
      body = base64Of(links.join("\n"));
      contentType = "text/plain; charset=utf-8";
    } else if (format === "links") {
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