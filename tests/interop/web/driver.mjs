// Drives clients/web-react in a headless browser, through its automation IDs, and speaks
// the same CLI contract as every other client (docs/CLIENT-ADAPTER.md), so interop.py can
// treat a browser like a command.
//
//   driver.mjs enroll --server <url> --ca <hex file> --data <dir> --token <token>
//   driver.mjs call   --server <url> --ca <hex file> --data <dir> --user <id> --peer <id> [--records N] [--relay-only]
//   driver.mjs answer --server <url> --ca <hex file> --data <dir> --user <id> [--relay-only] [--wait-ms N]

import { createReadStream, existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.resolve(here, "../../../clients/web-react/dist");
const args = process.argv.slice(2);
const mode = args[0];
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const say = (value) => console.log(JSON.stringify(value));

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".css": "text/css" };

function serve(port) {
  const server = createServer((request, response) => {
    const url = new URL(request.url, "http://localhost");
    const file = path.join(dist, url.pathname === "/" ? "index.html" : url.pathname);
    if (!file.startsWith(dist) || !existsSync(file)) {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { "content-type": TYPES[path.extname(file)] ?? "application/octet-stream" });
    createReadStream(file).pipe(response);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

async function main() {
  const data = flag("--data");
  const server = flag("--server");
  const ca = readFileSync(flag("--ca"), "utf8").trim();
  // IndexedDB belongs to an origin, so the same profile always gets the same port.
  const port = 20000 + (createHash("sha256").update(data).digest().readUInt16BE(0) % 20000);
  const site = await serve(port);
  const context = await chromium.launchPersistentContext(path.join(data, "browser"), { headless: true });
  const page = await context.newPage();
  const problems = [];
  page.on("pageerror", (e) => problems.push(String(e)));
  page.on("console", (m) => {
    if (m.type() === "error") {
      problems.push(m.text());
    }
  });
  const query = new URLSearchParams({ server, ca, profile: "default", relayOnly: args.includes("--relay-only") ? "1" : "0" });
  await page.goto(`http://127.0.0.1:${port}/?${query}`);
  const t = (screen, control) => page.getByTestId(`qalqon-${screen}-${control}`);

  const provider = await t("app", "provider").textContent();
  const waitStatus = async (expected, timeout = 60000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const status = (await t("app", "status").textContent()) ?? "";
      if (status.startsWith("error")) {
        throw new Error(`${status} ${problems.join(" | ")}`);
      }
      if (status.startsWith(expected)) {
        return status;
      }
      await page.waitForTimeout(25);
    }
    throw new Error(`timed out waiting for "${expected}": ${await t("app", "status").textContent()} ${problems.join(" | ")}`);
  };

  const logIn = async () => {
    await t("login", "user").fill(flag("--user"));
    await t("login", "password").fill(process.env.QALQON_PASSWORD);
    await t("login", "submit").click();
    await waitStatus("connected");
    say({ state: "connected" });
  };

  const waitResult = async (timeout) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const text = await t("interop", "result").textContent();
      if (text) {
        return JSON.parse(text);
      }
      const status = (await t("app", "status").textContent()) ?? "";
      if (status.startsWith("error")) {
        throw new Error(`${status} ${problems.join(" | ")}`);
      }
      await page.waitForTimeout(50);
    }
    throw new Error(`no result in time. ${problems.join(" | ")}`);
  };

  try {
    if (mode === "enroll") {
      await t("enrol", "token").fill(flag("--token"));
      await t("enrol", "submit").click();
      const status = await waitStatus("enrolled");
      say({ enrolled: { deviceId: status.split(" ")[1] }, provider });
    } else if (mode === "call") {
      await logIn();
      await t("peers", "user").fill(flag("--peer"));
      await t("interop", "records").fill(flag("--records") ?? "1000");
      await t("interop", "call").click();
      say({ ...(await waitResult(170000)), provider });
    } else if (mode === "answer") {
      await logIn();
      await t("interop", "answer").click();
      say({ ...(await waitResult(Number(flag("--wait-ms") ?? 60000) + 120000)), provider });
    } else {
      throw new Error("usage: driver.mjs <enroll|call|answer> ...");
    }
  } finally {
    await context.close();
    site.close();
  }
}

main().catch((e) => {
  say({ result: "error", error: String(e.message ?? e) });
  process.exit(1);
});
