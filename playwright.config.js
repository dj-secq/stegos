import path from "path";
import { fileURLToPath } from "url";

const root = path.dirname(fileURLToPath(import.meta.url));

export default {
  testDir: path.join(root, "tests"),
  testMatch: /browser\.spec\.js/,
  timeout: 180000,
  use: { baseURL: "http://127.0.0.1:8786" },
  webServer: {
    command: `"${path.join(root, "backend/venv/bin/python")}" -m flask --app stego_triage.app:app run --host 127.0.0.1 --port 8786 --no-reload`,
    cwd: root,
    env: {
      ...process.env,
      PYTHONPATH: path.join(root, "backend"),
      RUNTIME_ROOT: "/tmp/stego-triage-e2e",
      FRONTEND_ROOT: path.join(root, "frontend"),
    },
    url: "http://127.0.0.1:8786/api/health",
    reuseExistingServer: false,
    timeout: 30000,
  },
};
