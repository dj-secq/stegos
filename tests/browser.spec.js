import { execFileSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { expect, test } from "@playwright/test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = "/tmp/stego-bench.png";

function makeFixture() {
  execFileSync(path.join(root, "backend/venv/bin/python"), ["-c", `
from PIL import Image
Image.new("RGB", (32, 8), (20, 40, 60)).save("${fixture}")
with open("${fixture}", "ab") as handle:
    handle.write(b"\\nH4G{bench}\\n")
`]);
}

async function overflow(page) {
  return page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
}

async function runJob(page) {
  makeFixture();
  await page.goto("/");
  await expect(page).toHaveTitle("Stego Triage");
  await expect(page.getByRole("link", { name: "Domains" })).toHaveCount(0);
  const chooser = page.waitForEvent("filechooser");
  await page.locator("#drop-zone").press("Enter");
  await (await chooser).setFiles(fixture);
  await page.getByRole("button", { name: "Start analysis" }).click();
  await expect(page.locator("#leads")).toContainText("H4G{bench}", { timeout: 120000 });
  await expect(page.locator(".well img").first()).toBeVisible();
  await page.getByRole("button", { name: "Bit plane" }).click();
  await expect(page.getByRole("button", { name: "0 LSB" })).toBeVisible({ timeout: 120000 });
  await expect(page.getByRole("button", { name: "0 LSB" })).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("button", { name: "1", exact: true })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: /Strings/ }).click();
  await expect(page.locator(".check-panel").getByText(/strings|candidate/i).first()).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("link", { name: "Download this view" }).click();
  expect((await download).suggestedFilename()).toBeTruthy();
  expect(await overflow(page)).toBe(false);
  await page.getByRole("button", { name: "Delete job" }).click();
  await expect(page.locator("#work")).toBeHidden();
  await expect(page.locator("#drop-zone")).toBeVisible();
}

test("bench at 1280", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await runJob(page);
  expect(await overflow(page)).toBe(false);
});

test("bench at 390", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await runJob(page);
  expect(await overflow(page)).toBe(false);
});
