import { test } from "@playwright/test";
import fs from "node:fs";

test.skip(
  !fs.existsSync("src-tauri/target/debug/bundle/macos/ui.app"),
  "no debug app build — install tauri-driver and build first"
);

test("bootstrap + unlock smoke", async () => {
  // Real implementation requires tauri-driver setup (webdriver against the Tauri app).
  // Tracked as manual QA in docs/qa/admin-ui.md until tauri-driver lands stable on macOS.
});
