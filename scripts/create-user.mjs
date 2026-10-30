import { spawnSync } from "node:child_process";

const loginName = process.argv[2];
const displayName = process.argv[3];
const password = process.argv[4];

if (!loginName || !displayName || !password) {
  console.error("Usage: node scripts/create-user.mjs <login-name> <display-name> <password>");
  process.exit(1);
}

const sql = `INSERT INTO users (display_name, user_name, user_password, status)
VALUES ('${escapeSql(displayName)}', '${escapeSql(loginName)}', '${escapeSql(password)}', 'active');`;

const result = spawnSync(
  "npx",
  ["--yes", "wrangler", "d1", "execute", "stms", "--remote", "--command", sql],
  { stdio: "inherit" }
);

process.exit(result.status ?? 1);

function escapeSql(value) {
  return String(value).replaceAll("'", "''");
}
