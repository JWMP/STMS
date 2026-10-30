const PBKDF2_ITERATIONS = 100000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    if (url.pathname === "/api/login") {
      if (request.method !== "POST") {
        return json({ message: "不支援的請求。" }, 405, request);
      }
      return handleLogin(request, env);
    }

    if (url.pathname === "/api/teachers" && request.method === "GET") {
      return handleTeachers(env, request);
    }

    if (url.pathname === "/api/timetable" && request.method === "GET") {
      return handleTimetable(url, env, request);
    }

    return serveAsset(request, env);
  },
};

async function serveAsset(request, env) {
  const asset = await env.ASSETS.fetch(request);
  const type = asset.headers.get("content-type") || "";
  if (!type.includes("text/html")) return asset;

  const headers = new Headers(asset.headers);
  headers.set("Cache-Control", "no-store");
  return new Response(asset.body, {
    status: asset.status,
    statusText: asset.statusText,
    headers: headers,
  });
}

async function handleTeachers(env, request) {
  const result = await env.DB.prepare(
    "SELECT DISTINCT t.teacher AS teacher, u.display_name AS displayName FROM timetable t LEFT JOIN users u ON u.user_name = t.teacher COLLATE NOCASE ORDER BY t.teacher"
  ).all();
  return json({ teachers: result.results }, 200, request);
}

async function handleTimetable(url, env, request) {
  const teacher = (url.searchParams.get("teacher") || "").trim();
  if (!teacher) {
    return json({ lessons: [] }, 200, request);
  }

  const result = await env.DB.prepare(
    'SELECT week, lesson, "class" AS className, room, subject FROM timetable WHERE teacher = ?1 COLLATE NOCASE ORDER BY week, lesson'
  ).bind(teacher).all();
  return json({ lessons: result.results }, 200, request);
}

async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (error) {
    return json({ message: "請輸入登入名稱和密碼。" }, 400, request);
  }

  const loginName = String(body.loginName || "").trim();
  const password = String(body.password || "");
  if (!loginName || !password) {
    return json({ message: "請輸入登入名稱和密碼。" }, 400, request);
  }

  const user = await env.DB.prepare(
    "SELECT id, display_name, user_password, status FROM users WHERE user_name = ?1 COLLATE NOCASE"
  ).bind(loginName).first();

  if (!user || !(await passwordMatches(password, user.user_password))) {
    return json({ message: "登入名稱或密碼不正確。" }, 401, request);
  }

  if (user.status !== "active") {
    return json({ message: "此帳號已停用。" }, 403, request);
  }

  await env.DB.prepare(
    "UPDATE users SET last_login_at = datetime('now'), updated_at = datetime('now') WHERE id = ?1"
  ).bind(user.id).run();

  return json({ displayName: user.display_name }, 200, request);
}

async function passwordMatches(password, storedPassword) {
  const stored = String(storedPassword || "");
  if (stored.startsWith("pbkdf2$")) {
    const parts = stored.split("$");
    if (parts.length !== 4) return false;
    const actualHash = await hashPassword(password, hexToBytes(parts[2]));
    return timingSafeEqual(actualHash, parts[3]);
  }
  return timingSafeEqual(password, stored);
}

async function hashPassword(password, saltBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    key,
    256
  );
  return bytesToHex(bits);
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(function (byte) {
      return byte.toString(16).padStart(2, "0");
    })
    .join("");
}

function timingSafeEqual(left, right) {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) {
    diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return diff === 0;
}

function json(data, status, request) {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(request),
    },
  });
}

function corsHeaders(request) {
  return {
    "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    Vary: "Origin",
  };
}
