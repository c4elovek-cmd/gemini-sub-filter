/**
 * Cloudflare Pages Function — https://c4elovek.online/gemini
 *
 * Страница /gemini/ отдаётся как статика (GET), а проверка пароля идёт сюда:
 *
 *   POST /gemini  { "password": "..." }
 *     пароль верный  -> IP посетителя запоминается, и обычная ссылка
 *                       /workgemini начинает работать для этого IP
 *     пароль неверный -> 401
 *
 *   GET /gemini?check=1
 *     -> { "allowed": true|false } — заходит ли человек уже без пароля
 *
 * Запоминание IP живёт в KV-биндинге LINKS (он уже есть в проекте),
 * ключи с префиксом wg_. Пароль берётся из переменной окружения PASSWORD:
 * репозиторий публичный, код из него читают все.
 */

const KV_PREFIX = "wg_";
// Запомненный IP живёт недолго. 90 дней — слишком широкое окно: любой, кто
// окажется на этом IP за три месяца, заберёт подписку без пароля. Общий Wi-Fi,
// гостиница, NAT мобильного оператора, сосед по роутеру — всё это один и тот же
// адрес с точки зрения сервера.
//
// Отдельно стоит помнить: вводить пароль лучше при выключенном VPN. Иначе
// запомнится не твой адрес, а общий выход VPN-сервера, и подписку сможет
// забрать кто угодно, кто выходит через тот же сервер.
const IP_TTL_SECONDS = 14 * 24 * 3600;
const FAIL_TTL_SECONDS = 600;          // окно счётчика неудач
const MAX_FAILS = 10;

/**
 * Пароль берётся ТОЛЬКО из переменной окружения PASSWORD в настройках Pages.
 * Держать его в коде нельзя: всё, что лежит в репозитории, видно его
 * владельцу и тем, кому он репозиторий покажет. Если переменная не задана —
 * не пускаем никого.
 */
function resolvePassword(env) {
  const fromEnv = env && env.PASSWORD;
  if (typeof fromEnv === "string" && fromEnv.length >= 4) return fromEnv;
  return null;
}

function clientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    (request.headers.get("X-Forwarded-For") || "").split(",")[0].trim() ||
    "0.0.0.0"
  );
}

const ipKey = (ip) => KV_PREFIX + "ip_" + ip;
const failKey = (ip) => KV_PREFIX + "fail_" + ip;

function json(body, status, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-cache, no-store, must-revalidate",
      "Access-Control-Allow-Origin": "*",
      ...extra,
    },
  });
}

/** Публичный адрес для ссылки в подсказке про 401. */
function siteUrl(env, url) {
  if (env && env.PUBLIC_URL) return env.PUBLIC_URL;
  return new URL("/gemini/", url).toString();
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
  const store = env && env.LINKS ? env.LINKS : null;

  const readInt = async (key) => {
    if (!store) return 0;
    try {
      const n = parseInt((await store.get(key)) || "0", 10);
      return Number.isFinite(n) ? n : 0;
    } catch {
      return 0;
    }
  };

  // --- проверка без пароля: заходил ли этот IP
  if (request.method === "GET" && url.searchParams.get("check") === "1") {
    let allowed = false;
    if (store) {
      try {
        allowed = (await store.get(ipKey(ip))) !== null;
      } catch {
        allowed = false;
      }
    }
    return json({ allowed });
  }

  // --- сама проверка пароля
  if (request.method === "POST") {
    let submitted = "";
    try {
      const data = await request.json();
      submitted = String((data && data.password) || "");
    } catch {
      return json({ ok: false, error: "bad-request" }, 400);
    }

    // Ограничение попыток: пароль короткий, подбор не должен быть лёгким.
    const fails = await readInt(failKey(ip));
    if (fails >= MAX_FAILS) {
      return json({ ok: false, error: "too-many-tries" }, 429, { "Retry-After": "600" });
    }

    if (submitted !== password) {
      // Пароль неверный — копим счётчик.
      if (store) {
        try {
          await store.put(failKey(ip), String(fails + 1), {
            expirationTtl: FAIL_TTL_SECONDS,
          });
        } catch {
          /* без KV просто не считаем */
        }
      }
      return json({ ok: false, error: "wrong-password" }, 401);
    }

    // Верно — запоминаем IP и сбрасываем счётчик.
    if (store) {
      try {
        await store.put(ipKey(ip), new Date().toISOString(), {
          expirationTtl: IP_TTL_SECONDS,
        });
        await store.delete(failKey(ip));
      } catch {
        /* если KV недоступен — подписка не откроется, но страница работает */
      }
    }

    return json({ ok: true, ip });
  }

  // Остальное — обычная статическая страница.
  return next();
}