const MAX_BYTES = 25 * 1024 * 1024;
const DONE = new Set(["complete", "partial", "failed", "cancelled"]);
const STATUS_LABEL = {
  queued: "Queued",
  running: "Running",
  success: "Done",
  no_result: "No result",
  unavailable: "Unavailable",
  failed: "Failed",
  timeout: "Timed out",
  skipped: "Skipped",
  unsupported: "Unsupported",
  cancelled: "Cancelled",
  partial: "Partial",
  complete: "Complete",
};
const CHANNELS = ["R", "G", "B", "A", "RGB"];

const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");
const chosen = document.getElementById("chosen");
const startButton = document.getElementById("btn-start");
const deleteButton = document.getElementById("btn-delete");
const progress = document.getElementById("progress");
const warnings = document.getElementById("warnings");
const work = document.getElementById("work");
const views = document.getElementById("views");
const stageBody = document.getElementById("stage-body");
const stageMeta = document.getElementById("stage-meta");
const leads = document.getElementById("leads");
const checks = document.getElementById("checks");

const state = {
  file: null,
  job: null,
  timer: null,
  view: "original",
  channel: "R",
  bit: 0,
  frame: 0,
  remap: "",
  openCheck: "",
};

function setProgress(text) {
  progress.textContent = text;
}

function statusLabel(status) {
  return STATUS_LABEL[status] || "Queued";
}

function watchJob(job) {
  state.job = job;
  renderJob(job);
  window.clearInterval(state.timer);
  state.timer = null;
  if (!DONE.has(job.status)) {
    startButton.disabled = true;
    state.timer = window.setInterval(poll, 1000);
  } else {
    startButton.disabled = false;
  }
}

function artifactUrl(job, art, preview) {
  const base = `/api/jobs/${job.job_id}/artifacts/${encodeURIComponent(art.id)}`;
  return preview ? `${base}?preview=true` : base;
}

function eachArtifact(job, visit) {
  (job.analyzers || []).forEach((analyzer) => {
    (analyzer.artifacts || []).forEach((art) => visit(analyzer, art));
  });
}

function hydrate(art) {
  if (art.channel != null && art.bit != null) return art;
  const named = /^Channel ([RGBA]) Bit (\d)$/.exec(art.name || "");
  if (named) return Object.assign({}, art, { channel: named[1], bit: Number(named[2]) });
  const overlay = /^Superimposed RGB Bit (\d)$/.exec(art.name || "");
  if (overlay) return Object.assign({}, art, { channel: "RGB", bit: Number(overlay[1]) });
  const id = /^plane_([RGBA]|RGB)_(\d)\.png$/.exec(art.id || "");
  if (id) return Object.assign({}, art, { channel: id[1], bit: Number(id[2]) });
  return art;
}

function classify(analyzer, art) {
  const item = hydrate(art);
  if (item.frame != null || String(item.id || "").startsWith("gif_frame_")) return "frame";
  if (item.channel != null && item.bit != null) return "plane";
  const id = String(item.id || "");
  if (id.startsWith("remap_")) return "remap";
  if (id === "preview.png" || analyzer.id === "preview") return "preview";
  if (id.includes("spectrogram") || id.includes("waveform")) return "audio";
  if (String(item.media_type || "").startsWith("text/")) return "log";
  return "carved";
}

function collect(job, kind) {
  const found = [];
  eachArtifact(job, (analyzer, art) => {
    if (classify(analyzer, art) === kind) found.push(hydrate(art));
  });
  return found;
}

function planes(job) { return collect(job, "plane"); }
function frames(job) { return collect(job, "frame"); }

function copyButton(text) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Copy";
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    } catch (err) {
      button.textContent = "Copy failed";
    }
    window.setTimeout(() => { button.textContent = "Copy"; }, 1200);
  });
  return button;
}

function leadBlock(value, note, worth) {
  const row = document.createElement("div");
  row.className = worth ? "lead worth" : "lead";
  const text = document.createElement("p");
  text.className = "lead-value";
  text.textContent = value;
  const noteNode = document.createElement("p");
  noteNode.className = "hint";
  noteNode.textContent = note || "";
  row.append(text, copyButton(value));
  if (note) row.append(noteNode);
  return row;
}

function heading(text) {
  const node = document.createElement("h2");
  node.textContent = text;
  return node;
}

function downloadLink(job, art, label) {
  const link = document.createElement("a");
  link.href = artifactUrl(job, art, false);
  link.download = art.name || art.id;
  link.textContent = label || "Download";
  return link;
}

function imageNode(job, art, zoom) {
  const img = document.createElement("img");
  img.src = artifactUrl(job, art, true);
  img.alt = art.name || art.id;
  if (!zoom) img.loading = "lazy";
  if (zoom) {
    img.addEventListener("click", () => openLightbox(artifactUrl(job, art, true), img.alt));
  }
  return img;
}

function openLightbox(url, alt) {
  const box = document.createElement("div");
  box.className = "lightbox";
  box.tabIndex = -1;
  const img = document.createElement("img");
  img.src = url;
  img.alt = alt || "";
  box.append(img);
  box.addEventListener("click", () => box.remove());
  document.body.append(box);
  box.focus();
}

function setFile(file) {
  state.file = file || null;
  chosen.textContent = file ? file.name : "Drop a file here or press Enter to choose one";
}

function chooseFile() { fileInput.click(); }

dropZone.addEventListener("click", chooseFile);
dropZone.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    chooseFile();
  }
});
dropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropZone.classList.add("hot");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("hot"));
dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropZone.classList.remove("hot");
  if (event.dataTransfer.files[0]) setFile(event.dataTransfer.files[0]);
});
fileInput.addEventListener("change", () => setFile(fileInput.files[0]));

function resetWork() {
  window.clearInterval(state.timer);
  state.timer = null;
  state.job = null;
  state.view = "original";
  state.channel = "R";
  state.bit = 0;
  state.frame = 0;
  state.remap = "";
  state.openCheck = "";
  work.hidden = true;
  deleteButton.hidden = true;
  startButton.disabled = false;
  views.dataset.views = "";
  stageBody.dataset.key = "";
  leads.dataset.key = "";
  checks.dataset.key = "";
  stageMeta.textContent = "";
  warnings.hidden = true;
  warnings.replaceChildren();
}

function statusLine(job) {
  const input = job.input || {};
  const facts = [input.display_name, input.detected_mime || input.kind, input.size ? `${input.size} bytes` : ""]
    .filter(Boolean)
    .join(", ");
  const progressInfo = job.progress || {};
  if (job.status === "running" || job.status === "queued") {
    const current = progressInfo.current ? `Running ${progressInfo.current}.` : "Queued.";
    const count = progressInfo.total ? ` ${progressInfo.completed || 0} of ${progressInfo.total}.` : "";
    return `${facts} ${current}${count}`.trim();
  }
  if (job.status === "partial") return `${facts} Finished with a failed check.`.trim();
  if (job.status === "failed") return `${facts} Failed. ${job.error || ""}`.trim();
  if (job.status === "cancelled") return "Cancelled.";
  return `${facts} Finished.`.trim();
}

function paintWarnings(job) {
  const items = job.warnings || [];
  warnings.replaceChildren();
  warnings.hidden = items.length === 0;
  items.forEach((warning) => {
    const li = document.createElement("li");
    li.textContent = warning;
    warnings.append(li);
  });
}

function viewNames(job) {
  const names = [
    ["original", "Original"],
    ["channel", "Channel"],
    ["bit", "Bit plane"],
    ["remap", "Remap"],
    ["carved", "Carved"],
  ];
  if (frames(job).length) names.push(["frames", "Frames"]);
  return names;
}

function ensureViews(job) {
  const names = viewNames(job);
  const key = names.map((item) => item[0]).join(",");
  if (views.dataset.views !== key) {
    views.replaceChildren();
    names.forEach(([id, label]) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = label;
      button.dataset.view = id;
      button.addEventListener("click", () => {
        state.view = id;
        renderJob(state.job);
      });
      views.append(button);
    });
    views.dataset.views = key;
  }
  views.querySelectorAll("button").forEach((button) => {
    button.setAttribute("aria-pressed", button.dataset.view === state.view ? "true" : "false");
  });
}

function selectedPlane(job) {
  const all = planes(job);
  return all.find((item) => item.channel === state.channel && Number(item.bit) === Number(state.bit)) || null;
}

function controlRow(className, entries, current, onPick) {
  const row = document.createElement("div");
  row.className = className;
  entries.forEach((entry) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = entry.label;
    button.setAttribute("aria-pressed", entry.id === current ? "true" : "false");
    button.addEventListener("click", () => onPick(entry.id));
    row.append(button);
  });
  return row;
}

function filmstrip(job, items, pressed, onPick, caption) {
  const strip = document.createElement("div");
  strip.className = "filmstrip";
  items.forEach((art) => {
    const button = document.createElement("button");
    button.type = "button";
    button.setAttribute("aria-pressed", pressed(art) ? "true" : "false");
    button.append(imageNode(job, art, false));
    const cap = document.createElement("span");
    cap.className = "film-caption";
    cap.textContent = caption(art);
    button.append(cap);
    button.addEventListener("click", () => onPick(art));
    strip.append(button);
  });
  return strip;
}

function stageFigure(job, art, caption) {
  const wrap = document.createElement("div");
  const well = document.createElement("div");
  well.className = "well";
  if (art) {
    well.append(imageNode(job, art, true));
    const tools = document.createElement("div");
    tools.className = "stage-tools";
    tools.append(downloadLink(job, art, "Download this view"));
    wrap.append(well, tools);
  } else {
    const empty = document.createElement("p");
    empty.textContent = caption || "Nothing for this view yet.";
    well.append(empty);
    wrap.append(well);
  }
  return wrap;
}

function renderPlane(job, channelMode) {
  const all = planes(job);
  const present = CHANNELS.filter((name) => all.some((item) => item.channel === name));
  if (!present.length) return stageFigure(job, null, "No bit planes for this file.");
  if (!present.includes(state.channel)) state.channel = present[0];
  const wrap = document.createElement("div");
  wrap.className = channelMode ? "view-channel" : "view-bit";
  wrap.append(controlRow("channel-row", present.map((name) => ({ id: name, label: name })), state.channel, (id) => {
    state.channel = id;
    renderJob(state.job);
  }));
  wrap.append(controlRow("bit-row", [0, 1, 2, 3, 4, 5, 6, 7].map((bit) => ({
    id: String(bit),
    label: bit === 0 ? "0 LSB" : String(bit),
  })), String(state.bit), (id) => {
    state.bit = Number(id);
    renderJob(state.job);
  }));
  const note = document.createElement("p");
  note.className = "hint";
  note.textContent = "Bit 0 is the least significant bit. Arrow keys move the bit.";
  wrap.append(note);
  const current = selectedPlane(job);
  wrap.append(stageFigure(job, current, "This channel has no plane at that bit."));
  const stripItems = all.filter((item) => item.channel === state.channel).sort((a, b) => a.bit - b.bit);
  wrap.append(filmstrip(job, stripItems, (art) => Number(art.bit) === Number(state.bit), (art) => {
    state.bit = Number(art.bit);
    renderJob(state.job);
  }, (art) => `Bit ${art.bit}`));
  stageMeta.textContent = current ? `${current.channel} bit ${current.bit}` : "";
  return wrap;
}

function renderOriginal(job) {
  const kind = (job.input || {}).kind;
  const wrap = document.createElement("div");
  if (kind === "audio") {
    const player = document.createElement("audio");
    player.controls = true;
    player.preload = "metadata";
    player.src = `/api/jobs/${job.job_id}/input`;
    wrap.append(player);
    collect(job, "audio").forEach((art) => {
      wrap.append(stageFigure(job, art));
    });
    if (!collect(job, "audio").length) {
      const wait = document.createElement("p");
      wait.className = "hint";
      wait.textContent = "The waveform and spectrogram show up when those checks finish.";
      wrap.append(wait);
    }
    stageMeta.textContent = "Audio";
    return wrap;
  }
  if (kind === "pdf") {
    const card = document.createElement("div");
    card.className = "pdf-card";
    const title = document.createElement("p");
    title.textContent = (job.input || {}).display_name || "PDF";
    card.append(title);
    (job.analyzers || []).filter((item) => item.id === "pdfinfo" || item.id === "pdfid").forEach((analyzer) => {
      const line = document.createElement("p");
      line.textContent = `${analyzer.name}: ${analyzer.summary || analyzer.status}`;
      card.append(line);
    });
    const note = document.createElement("p");
    note.className = "hint";
    note.textContent = "The PDF is not rendered.";
    card.append(note);
    wrap.append(card);
    stageMeta.textContent = "PDF";
    return wrap;
  }
  const preview = collect(job, "preview")[0];
  wrap.append(stageFigure(job, preview, "The preview will show up when that check finishes."));
  stageMeta.textContent = preview ? "Original" : "";
  return wrap;
}

function renderRemap(job) {
  const items = collect(job, "remap");
  const wrap = document.createElement("div");
  if (!items.length) return stageFigure(job, null, "No color remaps for this file.");
  if (!items.some((item) => item.id === state.remap)) state.remap = items[0].id;
  const current = items.find((item) => item.id === state.remap);
  wrap.append(stageFigure(job, current));
  const grid = document.createElement("div");
  grid.className = "remap-grid";
  items.forEach((art) => {
    const button = document.createElement("button");
    button.type = "button";
    button.setAttribute("aria-pressed", art.id === state.remap ? "true" : "false");
    button.append(imageNode(job, art, false));
    button.addEventListener("click", () => {
      state.remap = art.id;
      renderJob(state.job);
    });
    grid.append(button);
  });
  wrap.append(grid);
  stageMeta.textContent = current ? current.name : "Remap";
  return wrap;
}

function renderCarved(job) {
  const items = collect(job, "carved");
  const wrap = document.createElement("div");
  if (!items.length) return stageFigure(job, null, "No carved file yet.");
  const image = items.find((item) => String(item.media_type || "").startsWith("image/"));
  if (image) wrap.append(stageFigure(job, image));
  items.forEach((art) => {
    const row = document.createElement("div");
    row.className = "carved-row";
    const name = document.createElement("strong");
    name.textContent = `${art.name || art.id} (${art.size || 0} bytes)`;
    row.append(name, downloadLink(job, art, "Download"));
    wrap.append(row);
  });
  stageMeta.textContent = "Carved";
  return wrap;
}

function renderFrames(job) {
  const items = frames(job).slice().sort((a, b) => a.frame - b.frame);
  const wrap = document.createElement("div");
  if (!items.length) return stageFigure(job, null, "No GIF frames.");
  if (!items.some((item) => item.frame === state.frame)) state.frame = items[0].frame;
  const current = items.find((item) => item.frame === state.frame);
  wrap.append(stageFigure(job, current));
  wrap.append(filmstrip(job, items, (art) => art.frame === state.frame, (art) => {
    state.frame = art.frame;
    renderJob(state.job);
  }, (art) => `Frame ${art.frame}, ${art.delay_ms || 0} ms`));
  stageMeta.textContent = current ? `Frame ${current.frame}, ${current.delay_ms || 0} ms` : "Frames";
  return wrap;
}

function renderStage(job) {
  const ids = [];
  eachArtifact(job, (_analyzer, art) => ids.push(art.id));
  const key = [state.view, state.channel, state.bit, state.frame, state.remap, job.status, ids.join("|")].join("~");
  if (stageBody.dataset.key === key) return;
  stageBody.dataset.key = key;
  stageMeta.textContent = "";
  let node;
  if (state.view === "channel" || state.view === "bit") node = renderPlane(job, state.view === "channel");
  else if (state.view === "remap") node = renderRemap(job);
  else if (state.view === "carved") node = renderCarved(job);
  else if (state.view === "frames") node = renderFrames(job);
  else node = renderOriginal(job);
  stageBody.replaceChildren(node);
}

function findingGroups(job) {
  const all = job.findings || [];
  const flags = all.filter((item) => item.kind === "candidate_flag");
  const phrases = all.filter((item) => item.kind === "passphrase_candidate");
  const hashes = all.filter((item) => item.kind === "hash_candidate" || /^[0-9a-fA-F]{32}$/.test(String(item.value || "").trim()));
  const barcodes = all.filter((item) => String(item.evidence || "").toLowerCase().includes("zbar") && item.kind !== "candidate_flag");
  const shown = new Set([...flags, ...phrases, ...hashes, ...barcodes]);
  const notes = all.filter((item) => !shown.has(item) && (item.kind === "observation" || item.kind === "checksum")).slice(0, 8);
  return { flags, phrases, hashes, barcodes, notes };
}

function renderLeads(job) {
  const groups = findingGroups(job);
  const carved = collect(job, "carved");
  const key = JSON.stringify({
    flags: groups.flags.map((item) => item.value),
    phrases: groups.phrases.map((item) => item.value),
    hashes: groups.hashes.map((item) => item.value),
    barcodes: groups.barcodes.map((item) => item.value),
    notes: groups.notes.map((item) => item.value),
    carved: carved.map((item) => item.id),
  });
  if (leads.dataset.key === key) return;
  leads.dataset.key = key;
  leads.replaceChildren();
  const empty = !groups.flags.length && !groups.phrases.length && !groups.hashes.length && !groups.barcodes.length && !carved.length && !groups.notes.length;
  if (empty) {
    const note = document.createElement("p");
    note.className = "hint";
    note.textContent = "No lead yet.";
    leads.append(note);
    return;
  }
  if (groups.flags.length) {
    leads.append(heading("Flags"));
    const note = document.createElement("p");
    note.className = "hint";
    note.textContent = "A match is not proof the flag is correct.";
    leads.append(note);
    groups.flags.forEach((item) => leads.append(leadBlock(item.value, [item.title, item.evidence].filter(Boolean).join(". "), true)));
  }
  if (groups.phrases.length) {
    leads.append(heading("Passphrases"));
    groups.phrases.forEach((item) => leads.append(leadBlock(item.value, "Put this in the password box and start again.", true)));
  }
  if (groups.hashes.length) {
    leads.append(heading("Hashes"));
    groups.hashes.forEach((item) => leads.append(leadBlock(item.value, "Take this to a hash identifier. This page does not look it up.", false)));
  }
  if (groups.barcodes.length) {
    leads.append(heading("Barcodes"));
    groups.barcodes.forEach((item) => leads.append(leadBlock(item.value, item.title || "Barcode", true)));
  }
  if (carved.length) {
    leads.append(heading("Carved files"));
    carved.forEach((art) => {
      const row = document.createElement("div");
      row.className = "carved-row";
      const name = document.createElement("strong");
      name.textContent = art.name || art.id;
      row.append(name, downloadLink(job, art, "Download"));
      leads.append(row);
    });
  }
  if (groups.notes.length) {
    leads.append(heading("Notes"));
    groups.notes.forEach((item) => {
      const worth = /decoded/i.test(item.title || "");
      leads.append(leadBlock(item.value, item.title || "", worth));
    });
  }
}

function logArtifacts(analyzer) {
  return (analyzer.artifacts || []).filter((art) => String(art.media_type || "").startsWith("text/"));
}

function renderChecks(job) {
  const key = (job.analyzers || []).map((item) => `${item.id}:${item.status}:${item.duration_ms}`).join("|") + "~" + state.openCheck;
  if (checks.dataset.key === key) return;
  checks.dataset.key = key;
  checks.replaceChildren();
  if (!(job.analyzers || []).length) {
    const wait = document.createElement("p");
    wait.className = "hint";
    wait.textContent = "Checks appear as they start.";
    checks.append(wait);
    return;
  }
  (job.analyzers || []).forEach((analyzer) => {
    const item = document.createElement("div");
    item.className = "check";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "check-button";
    const open = state.openCheck === analyzer.id;
    button.setAttribute("aria-expanded", open ? "true" : "false");
    const name = document.createElement("span");
    name.textContent = analyzer.name;
    const status = document.createElement("span");
    status.className = `status status-${analyzer.status || "queued"}`;
    status.textContent = statusLabel(analyzer.status);
    const timing = document.createElement("span");
    timing.textContent = analyzer.duration_ms ? `${analyzer.duration_ms} ms` : "";
    button.append(name, status, timing);
    const panel = document.createElement("div");
    panel.className = "check-panel";
    panel.hidden = !open;
    if (open) {
      const summary = document.createElement("p");
      summary.textContent = analyzer.summary || "No summary.";
      panel.append(summary);
      if (analyzer.error) {
        const error = document.createElement("p");
        error.className = "check-error";
        error.textContent = analyzer.error;
        panel.append(error);
      }
      (analyzer.artifacts || []).forEach((art) => {
        if (String(art.media_type || "").startsWith("text/")) return;
        const row = document.createElement("p");
        row.append(downloadLink(job, art, `Download ${art.name || art.id}`));
        panel.append(row);
      });
      const logs = logArtifacts(analyzer);
      if (logs.length) {
        const details = document.createElement("details");
        const images = (analyzer.artifacts || []).some((art) => String(art.media_type || "").startsWith("image/"));
        const flag = (analyzer.findings || []).some((finding) => finding.kind === "candidate_flag");
        if (!images && !flag) details.open = true;
        const label = document.createElement("summary");
        label.textContent = "Raw log";
        const pre = document.createElement("pre");
        pre.className = "raw-log";
        pre.textContent = "Loading output...";
        details.append(label, pre);
        panel.append(details);
        fetch(artifactUrl(job, logs[0], true))
          .then((response) => response.text())
          .then((text) => { pre.textContent = text; })
          .catch(() => { pre.textContent = "The log could not be loaded."; });
      }
    }
    button.addEventListener("click", () => {
      state.openCheck = open ? "" : analyzer.id;
      checks.dataset.key = "";
      renderChecks(job);
    });
    item.append(button, panel);
    checks.append(item);
  });
}

function renderJob(job) {
  if (!job) return;
  state.job = job;
  work.hidden = false;
  deleteButton.hidden = false;
  setProgress(statusLine(job));
  paintWarnings(job);
  ensureViews(job);
  renderStage(job);
  renderLeads(job);
  renderChecks(job);
}

async function poll() {
  if (!state.job) return;
  try {
    const response = await fetch(`/api/jobs/${state.job.job_id}`);
    if (!response.ok) return;
    const job = await response.json();
    renderJob(job);
    if (DONE.has(job.status)) {
      window.clearInterval(state.timer);
      state.timer = null;
      startButton.disabled = false;
    }
  } catch (err) {
    setProgress("The status check failed. The page will try again.");
  }
}

async function resumeCurrent() {
  try {
    const response = await fetch("/api/jobs/current");
    if (response.status === 204 || !response.ok) return;
    const job = await response.json();
    if (!job || !job.job_id) return;
    watchJob(job);
    poll();
  } catch (err) {
    /* The bench still works if this lookup fails. */
  }
}

startButton.addEventListener("click", async () => {
  if (startButton.disabled) return;
  if (!state.file) {
    setProgress("Choose a file first.");
    return;
  }
  if (state.file.size > MAX_BYTES) {
    setProgress("That file is over 25 MiB.");
    return;
  }
  const body = new FormData();
  body.append("file", state.file);
  body.append("profile", document.querySelector('input[name="profile"]:checked').value);
  body.append("flag_prefix", document.getElementById("flag-prefix").value.trim());
  body.append("password", document.getElementById("file-password").value);
  startButton.disabled = true;
  setProgress("Sending the file.");
  try {
    const response = await fetch("/api/jobs", { method: "POST", body });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 429 && payload.job_id) {
        setProgress("An analysis is already running. Delete it to start another.");
        watchJob({
          job_id: payload.job_id,
          status: "running",
          analyzers: [],
          findings: [],
          input: {},
        });
        poll();
        return;
      }
      startButton.disabled = false;
      setProgress(payload.error || "The file was not accepted.");
      return;
    }
    watchJob({
      job_id: payload.job_id,
      status: "queued",
      analyzers: [],
      findings: [],
      input: { display_name: state.file.name, size: state.file.size },
    });
    poll();
  } catch (err) {
    startButton.disabled = false;
    setProgress("The upload failed.");
  }
});

deleteButton.addEventListener("click", async () => {
  const jobId = state.job && state.job.job_id;
  if (!jobId) return;
  await fetch(`/api/jobs/${jobId}`, { method: "DELETE" }).catch(() => {});
  resetWork();
  setFile(null);
  fileInput.value = "";
  setProgress("Deleted. Drop another file.");
});

resumeCurrent();

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    const box = document.querySelector(".lightbox");
    if (box) {
      box.remove();
      event.preventDefault();
    }
    return;
  }
  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
  if (!state.job || (state.view !== "bit" && state.view !== "channel")) return;
  const tag = event.target && event.target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
  if (document.querySelector(".lightbox")) return;
  event.preventDefault();
  const delta = event.key === "ArrowRight" ? 1 : -1;
  state.bit = (Number(state.bit) + delta + 8) % 8;
  renderJob(state.job);
});
