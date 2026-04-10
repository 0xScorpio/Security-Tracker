/* ═══════════════════════════════════════════════════════════════════════════════
   app.js — Security Tracker Application Logic
   ═══════════════════════════════════════════════════════════════════════════════
   Single-file vanilla JS application powering the Security Tracker SPA.

   Architecture overview:
   ─────────────────────
   • State:        Singleton `state` object hydrated from localStorage on load.
   • Persistence:  localStorage (JSON state) + IndexedDB (binary evidence files).
   • Routing:      Hash-based (#/, #/timeline, #/machine/{id}).
   • Rendering:    Template-literal HTML → innerHTML injection (no virtual DOM).
   • Event wiring: Each render pass is followed by a `wire*()` call that attaches
                   event listeners to the fresh DOM nodes.

   File sections (in order):
   ─────────────────────────
   1. Constants & Default State
   2. Legacy Data Detection & State Hydration
   3. Phase Catalog & Ordering Helpers
   4. Configuration Objects, DOM Refs & Mutable State
   5. Core Utilities (persist, uid)
   6. IndexedDB Evidence CRUD
   7. Evidence Preview Overlay
   8. Storage Request & Image Filtering
   9. Shared UI Helpers (reusable across modals)
  10. Storage Metrics (app + browser quota display)
  11. Routing Helpers
  12. Date / Time Formatters
  13. Byte Formatting & Storage Meters
  14. Checklist Port Filtering & Applicability
  15. Checklist / Finding Lookups
  16. UI Feedback Helpers
  17. Progress Calculators
  18. Activity Logger
  19. Data Accessors (machine, credentials, findings, activity, evidence count)
  20. Navigation
  21. Renderers (Dashboard, Timeline, Checklist, Credentials, Findings, Notes,
                 Credential Inline Panel, Mind Map, Machine Detail)
  22. Router / Mount
  23. Modal Display (showDialogSafely)
  24. Event Wiring (wireDashboard, wireMachineDetail, wireChecklist,
                    wireMachineCredentials, wireFindings)
  25. Mind Map Interactivity (fullscreen, pan/zoom, SVG connectors, drag)
  26. Modal Functions (Finding View/Edit, Findings List, Notes, Evidence Gallery,
                       All Credentials, Quick Finding, Credential Edit)
  27. Global Event Listeners & Initial Mount
   ═══════════════════════════════════════════════════════════════════════════════ */


/* ───────────────────────────────────────────────
   1. Constants & Default State
   ─────────────────────────────────────────────── */

/** localStorage key for the serialized application state */
const STORAGE_KEY = 'securitytracker-template-v3';

/** IndexedDB database name for binary evidence file storage */
const EVIDENCE_DB_NAME = 'securitytracker-evidence-db';

/** IndexedDB schema version — bump when changing the object store structure */
const EVIDENCE_DB_VERSION = 1;

/** Name of the single object store inside the evidence database */
const EVIDENCE_STORE_NAME = 'evidence_files';

/* checklistPhases data is loaded from data.js */

/**
 * Default application state shape.
 * Any missing keys are back-filled during hydration so that older
 * localStorage payloads still work after schema changes.
 */
const defaultState = {
  ui: {
    sidebarCollapsed: false,
    mindmapMode: 'tree',
    machineTab: 'notes',
    openPhases: ['recon'],
    showAddMachine: false,
    showAddGlobalCred: false,
    showAddMachineCred: false,
    showAddFinding: false,
    mmPhase: 'all',
    checklistTaskFilter: 'all',
    mmViewState: {},
    activeNoteId: null,
  },
  reveal: {},
  machines: [],
  credentials: [],
  findings: [],
  activities: [],
};

/* ───────────────────────────────────────────────
   2. Legacy Data Detection & State Hydration
   ─────────────────────────────────────────────── */

/**
 * Detect whether the stored payload is the original hard-coded seed data
 * (machine IDs m1/m2, credential c1, findings f1/f2, etc.).  If so, we
 * clear it so the user starts fresh.
 */
function isLegacySeedData(payload) {
  const machineIds = (payload?.machines || []).map((machine) => machine.id).sort();
  const credentialIds = (payload?.credentials || []).map((credential) => credential.id).sort();
  const findingIds = (payload?.findings || []).map((finding) => finding.id).sort();
  const activityIds = (payload?.activities || []).map((activity) => activity.id).sort();

  return machineIds.join(',') === 'm1,m2'
    && credentialIds.join(',') === 'c1'
    && findingIds.join(',') === 'f1,f2'
    && activityIds.join(',') === 'a1,a10,a11,a12,a13,a14,a2,a3,a4,a5,a6,a7,a8,a9';
}

/**
 * Load persisted state from localStorage, merge with defaults so new keys
 * are always present, normalize legacy fields, and return the result.
 * Falls back to a fresh defaultState clone when nothing is stored.
 */
function hydrateState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return structuredClone(defaultState);
    const parsed = JSON.parse(raw);
    if (isLegacySeedData(parsed)) {
      localStorage.removeItem(STORAGE_KEY);
      return structuredClone(defaultState);
    }
    const merged = {
      ...structuredClone(defaultState),
      ...parsed,
      ui: { ...structuredClone(defaultState).ui, ...(parsed.ui || {}) },
    };
    merged.machines = (merged.machines || []).map((machine) => ({
      ...machine,
      selected_ports: machine.selected_ports || [],
      completed_items: machine.completed_items || [],
      item_notes: machine.item_notes || {},
      item_evidence: machine.item_evidence || {},
      archived_evidence: machine.archived_evidence || [],
      archived_credentials: machine.archived_credentials || [],
      note_tree: machine.note_tree || [],
      phase_notes: machine.phase_notes || {},
    }));
    merged.findings = (merged.findings || []).map((finding) => ({
      ...finding,
      evidence: finding.evidence || [],
      phase: finding.phase || 'osint',
      severity: finding.severity || 'info',
      category: finding.category || 'finding',
      parent_id: finding.parent_id || null,
      source_checklist_item_id: finding.source_checklist_item_id || null,
      created_at: finding.created_at || new Date().toISOString(),
      updated_at: finding.updated_at || finding.created_at || new Date().toISOString(),
    }));
    merged.credentials = (merged.credentials || []).map((cred) => ({
      ...cred,
      finding_id: cred.finding_id || null,
      created_at: cred.created_at || new Date().toISOString(),
    }));
    return merged;
  } catch {
    return structuredClone(defaultState);
  }
}

/** Live application state — mutated in place, persisted via persist(). */
const state = hydrateState();

/** Phase ID for the AD-specific checklist (only shown for Windows targets). */
const AD_CHECKLIST_PHASE_ID = 'active_directory_exploitation';

/* ───────────────────────────────────────────────
   3. Phase Catalog & Ordering Helpers
   ─────────────────────────────────────────────── */

/**
 * Return a deep-ish copy of checklistPhases, filtering out the AD phase
 * for non-Windows machines.  This ensures each machine sees only its
 * applicable phases.
 */
function checklistPhaseCatalogForMachine(machine) {
  const allPhases = checklistPhases.map((phase) => ({
    ...phase,
    items: [...(phase.items || [])],
  }));

  if (machine?.os_type === 'windows') return allPhases;

  return allPhases.filter((phase) => phase.id !== AD_CHECKLIST_PHASE_ID);
}

/** Resolve a phase ID to its human-readable name for the given machine. */
function phaseNameForMachine(machine, phaseId) {
  return checklistPhaseCatalogForMachine(machine).find((phase) => phase.id === phaseId)?.name || phaseId;
}

/* ── Phase ordering helpers (used for cross-phase parenting) ── */
function getPhaseOrderForMachine(machine) {
  return checklistPhaseCatalogForMachine(machine).map((phase) => phase.id);
}
function getPreviousPhase(phaseId, machine = null) {
  const order = getPhaseOrderForMachine(machine);
  const idx = order.indexOf(phaseId);
  return idx > 0 ? order[idx - 1] : null;
}
function getNextPhase(phaseId, machine = null) {
  const order = getPhaseOrderForMachine(machine);
  const idx = order.indexOf(phaseId);
  return (idx >= 0 && idx < order.length - 1) ? order[idx + 1] : null;
}
/**
 * Build eligible parents for a finding.
 * Same-phase: any finding in the same phase (except self/descendants).
 * Cross-phase: ONLY root-level findings may have a parent from the previous phase.
 *   A finding is "root-level" if it has no parent_id within its own phase.
 *   Cross-phase parents must be from the immediately previous phase only.
 */
function buildEligibleParents(machineId, findingPhase, excludeIds) {
  const machine = machineById(machineId);
  const all = machineFindings(machineId);
  const samePhase = all.filter(f => !excludeIds.has(f.id) && f.phase === findingPhase);
  const prevPhase = getPreviousPhase(findingPhase, machine);
  const crossPhase = prevPhase ? all.filter(f => !excludeIds.has(f.id) && f.phase === prevPhase) : [];
  return { samePhase, crossPhase, prevPhaseId: prevPhase };
}

/* ───────────────────────────────────────────────
   4. Configuration Objects, DOM Refs & Mutable State
   ─────────────────────────────────────────────── */

/** Maps machine status keys → display labels and CSS color classes. */
const statusConfig = {
  pending: { label: 'None', colorClass: 'status-pending' },
  scanning: { label: 'Initial Recon', colorClass: 'status-scanning' },
  user_shell: { label: 'Low-Level Exploited', colorClass: 'status-user_shell' },
  root_shell: { label: 'Root-Level Exploited', colorClass: 'status-root_shell' },
  completed: { label: 'Completed', colorClass: 'status-completed' },
};

const severityClass = {
  critical: 'severity-critical',
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
  info: 'severity-info',
};

/* ── Primary DOM anchors ── */
const main = document.getElementById('main');     // <main> content area
const sidebar = document.getElementById('sidebar'); // collapsible sidebar <aside>
const brand = document.getElementById('brand');     // brand link in sidebar header

/* ── Mutable module-level state ── */
let findingEvidenceBuffer = [];   // temp buffer for evidence during finding creation
let mmResizeObserver = null;      // ResizeObserver watching the mind-map container
let mmPanCleanup = null;          // teardown fn for the active pan/zoom listeners
let mmFsMachineId = null;         // machine ID currently in fullscreen mind map, or null
let persistTimer = null;          // debounce timer for persist()
let mainScrollLockTop = 0;        // saved scroll top when modal locks scroll
let mainScrollLockHandler = null; // event ref for the scroll-lock listener
let isMainScrollLocked = false;   // whether main scroll is currently frozen

/** Remove all scroll-lock classes and event listeners applied when a modal was open. */
function releaseModalLocks() {
  document.body.classList.remove('modal-active');
  document.documentElement.classList.remove('modal-active');
  document.documentElement.style.overflow = '';
  document.body.style.overflow = '';
  if (main) {
    if (mainScrollLockHandler) {
      main.removeEventListener('scroll', mainScrollLockHandler);
      mainScrollLockHandler = null;
    }
    main.style.overflow = 'auto';
  }
  isMainScrollLocked = false;
}

/* ───────────────────────────────────────────────
   5. Core Utilities
   ─────────────────────────────────────────────── */

/** Serialize the current state object to localStorage. */
function persist() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

/** Debounced persist — batches rapid state changes into a single write. */
function persistSoon() {
  if (persistTimer) return;
  persistTimer = setTimeout(() => { persistTimer = null; persist(); }, 300);
}

/** Generate a short random ID with the given prefix (e.g. uid('m') → 'm4kx9z'). */
function uid(prefix) {
  return `${prefix}${Math.random().toString(36).slice(2, 8)}`;
}

/* ───────────────────────────────────────────────
   6. IndexedDB Evidence CRUD
   ───────────────────────────────────────────────
   Evidence files (screenshots, documents) are stored as binary
   blobs in IndexedDB rather than localStorage (which has a ~5 MB
   limit and cannot handle binary data efficiently).
   ─────────────────────────────────────────────── */

let evidenceDbPromise;

/** Open (or create) the IndexedDB evidence database. Returns a cached promise. */
function openEvidenceDb() {
  if (evidenceDbPromise) return evidenceDbPromise;
  evidenceDbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(EVIDENCE_DB_NAME, EVIDENCE_DB_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(EVIDENCE_STORE_NAME)) {
        database.createObjectStore(EVIDENCE_STORE_NAME, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return evidenceDbPromise;
}

/** Store a File/Blob in IndexedDB. Returns a metadata object (id, name, type, size, created_at). */
async function putEvidenceFile(file) {
  const database = await openEvidenceDb();
  const record = {
    id: uid('e'),
    blob: file,
    name: file.name,
    type: file.type || 'application/octet-stream',
    size: file.size,
    created_at: nowStamp(),
  };
  await new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readwrite');
    tx.objectStore(EVIDENCE_STORE_NAME).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  return {
    id: record.id,
    name: record.name,
    type: record.type,
    size: record.size,
    created_at: record.created_at,
  };
}

/** Retrieve a full evidence record (including blob) by ID. */
async function getEvidenceFile(id) {
  const database = await openEvidenceDb();
  return new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readonly');
    const request = tx.objectStore(EVIDENCE_STORE_NAME).get(id);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

/** Remove an evidence record from IndexedDB by ID. */
async function deleteEvidenceFile(id) {
  const database = await openEvidenceDb();
  await new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readwrite');
    tx.objectStore(EVIDENCE_STORE_NAME).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Rename an existing evidence record (read → mutate → put back). */
async function updateEvidenceRecordName(id, name) {
  const database = await openEvidenceDb();
  await new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readwrite');
    const store = tx.objectStore(EVIDENCE_STORE_NAME);
    const request = store.get(id);
    request.onsuccess = () => {
      const record = request.result;
      if (!record) {
        resolve();
        return;
      }
      record.name = name;
      store.put(record);
    };
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Wipe all records from the evidence object store. */
async function clearEvidenceStore() {
  const database = await openEvidenceDb();
  await new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readwrite');
    tx.objectStore(EVIDENCE_STORE_NAME).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/* ───────────────────────────────────────────────
   7. Evidence Preview Overlay
   Opens a full-screen lightbox for images or an <object> embed for
   PDFs/other file types.  Manages blob URL lifecycle.
   ─────────────────────────────────────────────── */
/* ── Evidence Preview Overlay ─────────────────── */
let _evidenceOverlayUrl = null;

function openEvidencePreview(blobOrId) {
  const dialog = document.getElementById('evidencePreviewOverlay');
  if (!dialog) return;
  const img = dialog.querySelector('.ev-preview-img');
  const obj = dialog.querySelector('.ev-preview-object');
  const loading = dialog.querySelector('.ev-preview-loading');

  function show(blob, name, type) {
    if (_evidenceOverlayUrl) { URL.revokeObjectURL(_evidenceOverlayUrl); _evidenceOverlayUrl = null; }
    const url = URL.createObjectURL(blob);
    _evidenceOverlayUrl = url;
    const isImage = type && type.startsWith('image/');
    if (isImage) {
      img.src = url;
      img.alt = name || 'Evidence';
      img.style.display = '';
      obj.style.display = 'none';
    } else {
      obj.data = url;
      obj.type = type || 'application/octet-stream';
      obj.style.display = '';
      img.style.display = 'none';
    }
    loading.style.display = 'none';
  }

  /* Reset display states */
  loading.style.display = '';
  img.style.display = 'none';
  obj.style.display = 'none';

  /* showModal() puts it in the top layer, above all other dialogs */
  try {
    if (!dialog.open) dialog.showModal();
  } catch {
    return;
  }

  if (blobOrId instanceof Blob) {
    show(blobOrId, '', blobOrId.type);
    return;
  }

  /* id string → fetch from IndexedDB */
  getEvidenceFile(blobOrId).then(record => {
    if (!record?.blob) { closeEvidencePreview(); return; }
    show(record.blob, record.name, record.type);
  }).catch(() => {
    closeEvidencePreview();
  });
}

function closeEvidencePreview() {
  const dialog = document.getElementById('evidencePreviewOverlay');
  if (!dialog) return;
  if (dialog.open) dialog.close();
  if (_evidenceOverlayUrl) { URL.revokeObjectURL(_evidenceOverlayUrl); _evidenceOverlayUrl = null; }
  const img = dialog.querySelector('.ev-preview-img');
  const obj = dialog.querySelector('.ev-preview-object');
  if (img) { img.src = ''; img.style.display = 'none'; }
  if (obj) { obj.data = ''; obj.style.display = 'none'; }
}

/* Close preview on backdrop click */
document.addEventListener('DOMContentLoaded', () => {
  const dlg = document.getElementById('evidencePreviewOverlay');
  if (dlg) dlg.addEventListener('click', (e) => {
    if (e.target === dlg) closeEvidencePreview();
  });
});

/* ───────────────────────────────────────────────
   8. Storage Request & Image Filtering
   ─────────────────────────────────────────────── */

/** Ask the browser to keep our origin’s storage persistent (best-effort). */
async function requestPersistentStorage() {
  if (!navigator.storage?.persist) return;
  try {
    await navigator.storage.persist();
  } catch {
  }
}

/** Filter a FileList/array down to only image/* MIME types. */
function getImageFilesFromList(files) {
  return Array.from(files || []).filter((file) => file && file.type && file.type.startsWith('image/'));
}

/* ═══════════════════════════════════════════════
   Shared UI Helpers
   ═══════════════════════════════════════════════ */

/** Close a <dialog> when user clicks its backdrop. Optionally run onClose callback. */
function addBackdropClose(modal, onClose) {
  modal.addEventListener('click', function backdropClose(e) {
    if (e.target !== modal) return;
    if (onClose) onClose();
    modal.close();
    modal.removeEventListener('click', backdropClose);
  });
}

/** Wire up a dropzone element for drag-and-drop / click / paste of image files. */
function wireDropzone(dropEl, inputEl, onFiles) {
  if (!dropEl || !inputEl) return;
  dropEl.addEventListener('click', () => inputEl.click());
  inputEl.addEventListener('change', (e) => { onFiles(e.target.files || []); e.target.value = ''; });
  dropEl.addEventListener('dragover', (e) => { e.preventDefault(); dropEl.classList.add('drag-over'); });
  dropEl.addEventListener('dragleave', () => dropEl.classList.remove('drag-over'));
  dropEl.addEventListener('drop', (e) => { e.preventDefault(); dropEl.classList.remove('drag-over'); onFiles(e.dataTransfer?.files || []); });
  dropEl.addEventListener('paste', (e) => { const imgs = getImageFilesFromList(e.clipboardData?.files || []); if (imgs.length) { e.preventDefault(); onFiles(imgs); } });
  dropEl.addEventListener('mouseenter', () => dropEl.focus({ preventScroll: true }));
}

/** Return <option> HTML for severity dropdowns. */
function severityOptionsHtml(selected = 'high') {
  return ['critical','high','medium','low','info'].map(s =>
    `<option value="${s}"${s === selected ? ' selected' : ''}>${s.charAt(0).toUpperCase() + s.slice(1)}</option>`
  ).join('');
}

/** Return <option> HTML for phase dropdowns. */
function phaseOptionsHtml(machinePhases, selected = '') {
  return machinePhases.map(p =>
    `<option value="${p.id}"${p.id === selected ? ' selected' : ''}>${p.name}</option>`
  ).join('');
}

/** Build parent-finding <option> + <optgroup> HTML for a given phase. */
function parentFindingOptionsHtml(machineId, phaseId, excludeIds, selectedId, machine) {
  const ep = buildEligibleParents(machineId, phaseId, excludeIds);
  let html = ep.samePhase.map(p =>
    `<option value="${p.id}"${p.id === selectedId ? ' selected' : ''}>${p.title} [${p.severity}]</option>`
  ).join('');
  if (ep.crossPhase.length) {
    const prevLabel = phaseNameForMachine(machine, ep.prevPhaseId);
    html += `<optgroup label="Cross-phase (${prevLabel})">` +
      ep.crossPhase.map(p => `<option value="${p.id}"${p.id === selectedId ? ' selected' : ''}>${p.title} [${p.severity}]</option>`).join('') +
      '</optgroup>';
  }
  return html;
}

/** Wire a phase <select> to dynamically update a parent-finding <select>. */
function wirePhaseParentSync(container, phaseSelectId, parentSelectId, machineId, excludeIds, selectedParentId, machine) {
  container.querySelector('#' + phaseSelectId)?.addEventListener('change', (e) => {
    const sel = container.querySelector('#' + parentSelectId);
    if (!sel) return;
    sel.innerHTML = '<option value="">Root Level (no parent)</option>' +
      parentFindingOptionsHtml(machineId, e.target.value, excludeIds, selectedParentId, machine);
  });
}

/** Return the set [id, ...all descendants] of a finding by following parent_id chains. */
function getDescendantIds(id, all) {
  return [id, ...all.filter(f => f.parent_id === id).flatMap(c => getDescendantIds(c.id, all))];
}

/** Two-click confirm guard. Returns true if already armed (proceed). Otherwise arms and returns false. */
function armConfirmButton(btn, revertText = '🗑') {
  if (btn.classList.contains('confirm-armed')) return true;
  btn.classList.add('confirm-armed');
  const orig = revertText ?? btn.textContent;
  btn.textContent = 'Sure?';
  setTimeout(() => { if (btn.isConnected) { btn.classList.remove('confirm-armed'); btn.textContent = orig; } }, 3000);
  return false;
}

/** Return <option> HTML for credential type dropdowns. */
function credTypeOptionsHtml(selected = 'plain') {
  const types = [['plain','Plain Text'],['hash','Hash'],['key','SSH Key'],['token','Token']];
  return types.map(([v,l]) =>
    `<option value="${v}"${v === selected ? ' selected' : ''}>${l}</option>`
  ).join('');
}

/** Archive a finding's evidence and linked credentials into machine.archived_*.
 *  Returns the number of archived credentials. */
function archiveFindingData(machine, finding, sourceType, excludeEvidenceId) {
  if (!machine.archived_evidence) machine.archived_evidence = [];
  if (!machine.archived_credentials) machine.archived_credentials = [];
  const now = new Date().toISOString();
  for (const ev of (finding.evidence || [])) {
    if (excludeEvidenceId && ev.id === excludeEvidenceId) continue;
    machine.archived_evidence.push({ ...ev, archived_at: now, source_finding_title: finding.title, source_finding_id: finding.id, source_type: sourceType });
  }
  const linkedCreds = state.credentials.filter(c => c.finding_id === finding.id);
  for (const cred of linkedCreds) {
    machine.archived_credentials.push({ ...cred, finding_id: null, archived_at: now, source_finding_title: finding.title, source_finding_id: finding.id, source_type: sourceType });
    state.credentials = state.credentials.filter(c => c.id !== cred.id);
  }
  return linkedCreds.length;
}

/* ───────────────────────────────────────────────
  10. Storage Metrics
   ─────────────────────────────────────────────── */

/** Sum total bytes of all evidence blobs stored in IndexedDB. */
async function getEvidenceUsageBytes() {
  const database = await openEvidenceDb();
  return new Promise((resolve, reject) => {
    const tx = database.transaction(EVIDENCE_STORE_NAME, 'readonly');
    const store = tx.objectStore(EVIDENCE_STORE_NAME);
    let total = 0;
    const cursor = store.openCursor();
    cursor.onsuccess = (event) => {
      const row = event.target.result;
      if (!row) {
        resolve(total);
        return;
      }
      const value = row.value || {};
      total += Number(value.size || value.blob?.size || 0);
      row.continue();
    };
    cursor.onerror = () => reject(cursor.error);
  });
}

/** Calculate combined storage: localStorage state JSON + IndexedDB evidence blobs. */
async function getAppUsageBytes() {
  const localRaw = localStorage.getItem(STORAGE_KEY) || '';
  const stateBytes = new TextEncoder().encode(localRaw).length;
  const evidenceBytes = await getEvidenceUsageBytes();
  return {
    total: stateBytes + evidenceBytes,
    stateBytes,
    evidenceBytes,
  };
}

/* ───────────────────────────────────────────────
  11. Routing Helpers
   ─────────────────────────────────────────────── */

/** Return the current hash path, e.g. “/”, “/timeline”, or “/machine/m4kx9z”. */
function routePath() {
  return (window.location.hash.replace('#', '') || '/').trim();
}

/** Extract a machine ID from a path like “/machine/m4kx9z”.  Returns null if no match. */
function parseMachineRoute(path) {
  const match = path.match(/^\/machine\/([^/]+)$/);
  return match ? match[1] : null;
}

/* ───────────────────────────────────────────────
  12. Date / Time Formatters
   ─────────────────────────────────────────────── */

/** Current time as an ISO-8601 string (used for timestamps on new records). */
function nowStamp() {
  return new Date().toISOString();
}

/** Full locale date string: "Jan 5, 2025, 14:32:18". */
function formatDate(value) {
  return new Date(value).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

/** Short locale date: "Jan 5, 14:32". */
function formatShort(value) {
  return new Date(value).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

/** Time-only string in 24-hour format. */
function formatTime(value) {
  return new Date(value).toLocaleTimeString(undefined, { hour12: false });
}

/** Military-style timestamp: "14:32:18 05/01/25". */
function formatDateTimeMilitary(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (isNaN(d)) return '—';
  const dd = String(d.getDate()).padStart(2, '0');
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const yy = String(d.getFullYear()).slice(-2);
  const hh = String(d.getHours()).padStart(2, '0');
  const mi = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mi}:${ss} ${dd}/${mm}/${yy}`;
}

/** Human-friendly relative time string: "3 minutes ago", "about 2 hours ago". */
function relative(value) {
  const diff = Date.now() - new Date(value).getTime();
  const mins = Math.max(1, Math.floor(diff / 60000));
  if (mins < 60) return `${mins} minute${mins !== 1 ? 's' : ''} ago`;
  const hours = Math.floor(mins / 60);
  return `about ${hours} hour${hours !== 1 ? 's' : ''} ago`;
}

/* ───────────────────────────────────────────────
  13. Byte Formatting & Storage Meters
   ─────────────────────────────────────────────── */

/** Convert a raw byte count to a human-friendly string like "1.23 MB". */
function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const digits = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[unitIndex]}`;
}

/**
 * Refresh the storage meter labels on the dashboard.  Reads both the app
 * usage (localStorage + IndexedDB) and the browser Storage API quota.
 */
async function updateStorageMeters() {
  const appMeter = document.getElementById('appStorageMeter');
  const browserMeter = document.getElementById('browserStorageMeter');
  if (!appMeter && !browserMeter) return;

  try {
    const appUsage = await getAppUsageBytes();
    if (appMeter) {
      appMeter.textContent = `App Data: ${formatBytes(appUsage.total)} (State ${formatBytes(appUsage.stateBytes)} + Evidence ${formatBytes(appUsage.evidenceBytes)})`;
    }
  } catch {
    if (appMeter) appMeter.textContent = 'App Data: unavailable';
  }

  if (!navigator.storage?.estimate) {
    if (browserMeter) browserMeter.textContent = 'Browser Quota: unavailable in this browser';
    return;
  }

  try {
    const estimate = await navigator.storage.estimate();
    const used = estimate.usage || 0;
    const quota = estimate.quota || 0;
    const percent = quota ? Math.min(100, Math.round((used / quota) * 100)) : 0;
    if (browserMeter) {
      browserMeter.textContent = `Browser Quota: ${formatBytes(used)} / ${formatBytes(quota)} (${percent}%)`;
    }
  } catch {
    if (browserMeter) browserMeter.textContent = 'Browser Quota: unavailable';
  }
}

/* ───────────────────────────────────────────────
  14. Checklist Port Filtering & Applicability
   Determines which checklist items are visible for a given machine
   based on selected recon ports, OS type, and phase.
   ─────────────────────────────────────────────── */

/** Parse port numbers from an item name like "SMB (445)" → ["445"]. */
function extractPortsFromReconItem(item) {
  const match = item.name.match(/\(([^)]+)\)/);
  if (!match) return [];
  const ports = (match[1] || '').match(/\d+/g) || [];
  return Array.from(new Set(ports));
}

/** Collect all unique port numbers referenced in the recon phase items. */
function getReconPortOptions() {
  const reconPhase = checklistPhases.find((phase) => phase.id === 'recon');
  if (!reconPhase) return [];
  const portSet = new Set();
  reconPhase.items.forEach((item) => {
    extractPortsFromReconItem(item).forEach((port) => portSet.add(port));
  });
  return Array.from(portSet).sort((a, b) => Number(a) - Number(b));
}

/**
 * Decide whether a checklist item applies to the given machine.
 * Filters on: AD phase (windows-only), recon port selection,
 * and OS-prefixed items ("Linux:" / "Windows:") in exploitation phases.
 */
function isItemApplicableForMachine(machine, phaseId, item) {
  if (phaseId === AD_CHECKLIST_PHASE_ID) {
    return machine.os_type === 'windows';
  }

  if (phaseId === 'recon') {
    const selectedPorts = new Set(machine.selected_ports || []);
    if (!selectedPorts.size) return true;
    const itemPorts = extractPortsFromReconItem(item);
    if (!itemPorts.length) return true;
    return itemPorts.some((port) => selectedPorts.has(port));
  }

  const OS_FILTERED_PHASES = ['exploitation', 'post_exploitation', 'persistence'];
  if (OS_FILTERED_PHASES.includes(phaseId)) {
    const itemName = (item.name || '').toLowerCase();
    if (itemName.startsWith('linux:')) return machine.os_type === 'linux';
    if (itemName.startsWith('windows:')) return machine.os_type === 'windows';
  }

  return true;
}

/* ───────────────────────────────────────────────
  15. Checklist / Finding Lookups
   ─────────────────────────────────────────────── */

/** Find a checklist item by ID across all phases (uses Windows catalog for completeness). */
function checklistItemById(itemId) {
  return checklistPhaseCatalogForMachine({ os_type: 'windows' }).flatMap((phase) => phase.items).find((item) => item.id === itemId) || null;
}

/** Find which phase contains the given checklist item ID. */
function checklistPhaseForItem(itemId) {
  return checklistPhaseCatalogForMachine({ os_type: 'windows' }).find((phase) => phase.items.some((item) => item.id === itemId)) || null;
}

/* ───────────────────────────────────────────────
  16. UI Feedback Helpers
   ─────────────────────────────────────────────── */

/** Convert an activity action string like "add_machine" → "Add Machine". */
function formatActionLabel(action) {
  return String(action || '').replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

/** Show a brief floating "Copied!" toast near the given anchor element. */
function showCopyFeedback(anchor, message = 'Copied!') {
  if (!anchor) return;
  document.querySelectorAll('.copy-feedback-toast').forEach((toast) => toast.remove());

  const rect = anchor.getBoundingClientRect();
  const toast = document.createElement('div');
  toast.className = 'copy-feedback-toast';
  toast.textContent = message;
  toast.style.left = `${Math.round(rect.right + 8)}px`;
  toast.style.top = `${Math.round(rect.top + rect.height / 2)}px`;
  document.body.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.add('show');
  });

  window.setTimeout(() => {
    toast.classList.remove('show');
    window.setTimeout(() => toast.remove(), 150);
  }, 900);
}

/* ───────────────────────────────────────────────
  17. Progress Calculators
   ─────────────────────────────────────────────── */

/** All checklist items applicable to this machine (respects OS + port filters). */
function getApplicableItems(machine) {
  return checklistPhaseCatalogForMachine(machine).reduce((items, phase) => {
    const filteredItems = phase.items.filter((item) => isItemApplicableForMachine(machine, phase.id, item));
    return [...items, ...filteredItems];
  }, []);
}

/** Percentage (0–100) of items completed within a single checklist phase. */
function getPhaseProgress(phase, completedItems) {
  const total = phase.items.length;
  if (!total) return 0;
  const completed = phase.items.filter((item) => completedItems.includes(item.id)).length;
  return Math.round((completed / total) * 100);
}

/** Overall checklist progress (0–100) across all applicable phases for a machine. */
function getTotalProgress(machine) {
  const applicable = getApplicableItems(machine);
  if (!applicable.length) return 0;
  const completed = applicable.filter((item) => (machine.completed_items || []).includes(item.id)).length;
  return Math.round((completed / applicable.length) * 100);
}

/* ───────────────────────────────────────────────
  18. Activity Logger
   ─────────────────────────────────────────────── */

/** Push a timestamped activity entry to the front of state.activities. */
function addActivity(action, details, machineId) {
  state.activities.unshift({
    id: uid('a'),
    action,
    details,
    machine_id: machineId,
    timestamp: nowStamp(),
  });
}

/* ───────────────────────────────────────────────
  19. Data Accessors
   Convenience functions for querying the in-memory state.
   ─────────────────────────────────────────────── */

/** Look up a machine object by its ID. */
function machineById(id) {
  return state.machines.find((machine) => machine.id === id);
}

/** All credentials associated with a machine. */
function machineCredentials(machineId) {
  return state.credentials.filter((credential) => credential.machine_id === machineId);
}

/** Map a phase ID to its brand colour hex string (used in SVG & inline styles). */
function phaseColor(pid) {
  if (pid === 'osint') return '#a78bfa';
  if (pid === 'recon') return '#22d3ee';
  if (pid === 'exploitation') return '#f97316';
  if (pid === AD_CHECKLIST_PHASE_ID) return '#facc15';
  if (pid === 'post_exploitation') return '#f43f5e';
  if (pid === 'persistence') return '#3b82f6';
  return 'var(--text)';
}

/** All findings belonging to a machine (active + archived). */
function machineFindings(machineId) {
  return state.findings.filter((finding) => finding.machine_id === machineId);
}

/** Activity log entries scoped to a specific machine. */
function machineActivity(machineId) {
  return state.activities.filter((activity) => activity.machine_id === machineId);
}

/** Total evidence file count for a machine (findings + checklist items). */
function machineEvidenceCount(machineId) {
  const findingEvidence = machineFindings(machineId).reduce((sum, f) => sum + (f.evidence || []).length, 0);
  const machine = machineById(machineId);
  const itemEvidence = machine ? Object.values(machine.item_evidence || {}).reduce((sum, arr) => sum + arr.length, 0) : 0;
  return findingEvidence + itemEvidence;
}

/* ───────────────────────────────────────────────
  20. Navigation
   ─────────────────────────────────────────────── */

/** Highlight the active sidebar nav link based on the current hash route. */
function setNav() {
  const path = routePath();
  document.querySelectorAll('.nav-item').forEach((item) => {
    const target = item.dataset.route;
    const active = path === target || (target !== '/' && path.startsWith(target));
    item.classList.toggle('active', active);
  });
}

/* ───────────────────────────────────────────────
  21. Renderers
   Each render* function returns an HTML string.  After injection
   into the DOM via innerHTML, a matching wire* function attaches
   the event listeners.
   ─────────────────────────────────────────────── */

/** Render the dashboard page: machine cards grid with progress, status, and storage meters. */
function renderDashboard() {
  const cards = state.machines.map((machine, index) => {
    const status = statusConfig[machine.status] || statusConfig.pending;
    const progress = getTotalProgress(machine);
    return `
      <article class="card machine-card animate-fade-in stagger-${Math.min(index + 1, 6)}" data-machine-id="${machine.id}">
        <div class="card-top">
          <span class="status"><span class="status-dot ${status.colorClass}"></span>${status.label}</span>
          <div class="actions">
            <span class="badge">${machine.os_type === 'windows' ? 'WIN' : 'LNX'}</span>
            <button class="icon-btn" data-delete-machine="${machine.id}" title="Delete">🗑</button>
          </div>
        </div>
        <div style="margin-top:.8rem">
          <div class="mono">${machine.ip}</div>
          ${machine.hostname ? `<div class="small mono" style="margin-top:.3rem">${machine.hostname}</div>` : ''}
        </div>
        ${machine.tags?.length ? `<div class="tags">${machine.tags.map((tag) => `<span class="badge">${tag}</span>`).join('')}</div>` : ''}
        <div class="progress">
          <div class="progress-row"><span class="dim">Progress</span><span style="color:var(--green)" class="mono">${progress}%</span></div>
          <div class="progress-bar"><div class="progress-fill" style="width:${progress}%"></div></div>
        </div>
        <div class="small mono dim" style="margin-top:.7rem">${formatShort(machine.created_at)}</div>
      </article>
    `;
  }).join('');

  return `
    <section>
      <div class="header-row">
        <div>
          <h1>Target Machines</h1>
          <div class="sub">${state.machines.length} machine${state.machines.length !== 1 ? 's' : ''} tracked</div>
          <div class="small dim" id="appStorageMeter">App Data: estimating...</div>
          <div class="small dim" id="browserStorageMeter">Browser Quota: estimating...</div>
        </div>
        <div class="actions">
          <button class="btn btn-ghost" id="importXmlBtn" title="Import machines from XML">⬆ Import</button>
          <button class="btn btn-ghost" id="exportXmlBtn" title="Export all data to XML">⬇ Export</button>
          <button class="btn btn-ghost" id="resetMachinesBtn">Reset Machines</button>
          <button class="btn btn-primary" id="openMachineModal">Add Machine</button>
        </div>
      </div>
      ${state.machines.length ? `<div class="grid">${cards}</div>` : `<div class="empty"><h3>No targets yet</h3><div class="small">Add your first machine to start tracking</div></div>`}
    </section>
  `;
}

/** Render the global activity timeline page, grouped by calendar day. */
function renderTimeline() {
  const grouped = state.activities.reduce((acc, activity) => {
    const day = new Date(activity.timestamp).toDateString();
    if (!acc[day]) acc[day] = [];
    acc[day].push(activity);
    return acc;
  }, {});

  return `
    <section>
      <div class="header-row">
        <div>
          <h1>◷ Activity Timeline</h1>
          <div class="sub">${state.activities.length} event${state.activities.length !== 1 ? 's' : ''} logged</div>
        </div>
      </div>
      <div class="timeline-scroll">
        ${Object.entries(grouped).map(([day, entries]) => `
          <div class="date-head">
            <span class="badge mono">${new Date(day).toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })}</span>
            <div class="hr"></div>
            <span class="small dim">${entries.length} events</span>
          </div>
          <div class="group">
            ${entries.map((entry) => {
              const machine = machineById(entry.machine_id);
              return `
                <div class="event ${entry.action}">
                  <div style="display:flex;gap:.45rem;align-items:center;flex-wrap:wrap"><span class="badge mono">${formatActionLabel(entry.action)}</span><span>${entry.details}</span></div>
                  <div class="small" style="margin-top:.2rem">${formatTime(entry.timestamp)} · ${relative(entry.timestamp)}${machine ? ` · <span class="mono" style="color:var(--green)">${machine.ip}</span>` : ''}</div>
                </div>
              `;
            }).join('')}
          </div>
        `).join('')}
      </div>
    </section>
  `;
}

/** Replace <TARGET_IP> placeholders in checklist commands with the machine’s actual IP. */
function substituteTargetIp(cmd, ip) {
  return cmd.replace(/<TARGET_IP>|<target-ip>|<TARGET-IP>|<Target-IP>|<Target-ip>/gi, ip);
}

/** Return the filterable, OS-specific set of checklist phases for a machine. */
function checklistPhasesFor(machine) {
  const activePhases = checklistPhaseCatalogForMachine(machine);

  return activePhases
    .map((phase) => ({
      ...phase,
      items: phase.items.filter((item) => isItemApplicableForMachine(machine, phase.id, item)),
    }))
    .filter((phase) => phase.items.length > 0);
}

/** Emoji icons mapped to each phase ID (used in accordion headers and mind map). */
const PHASE_EMOJI = {
  osint:            '🔍',
  recon:            '📡',
  exploitation:     '💥',
  [AD_CHECKLIST_PHASE_ID]: '🪟',
  post_exploitation:'🦾',
  persistence:      '🔒',
};

/**
 * Render the interactive checklist accordion for a machine detail page.
 * Includes port filter bar, phase accordions with check items, command blocks,
 * evidence dropzones, and completed/incomplete task filter toggles.
 */
function renderChecklist(machine) {
  const completedItems = machine.completed_items || [];
  const allPhases = checklistPhasesFor(machine);
  const totalItems = getApplicableItems(machine).length;
  const taskFilter = state.ui.checklistTaskFilter || 'all';
  const phases = allPhases
    .map((phase) => ({
      ...phase,
      items: phase.items.filter((item) => {
        const done = completedItems.includes(item.id);
        if (taskFilter === 'completed') return done;
        if (taskFilter === 'incomplete') return !done;
        return true;
      }),
    }))
    .filter((phase) => phase.items.length > 0);

  return `
    <div class="mt-4">
      <div class="checklist-head">
        <div class="checklist-head-left">
          <button class="btn btn-ghost checklist-btn-reset" id="resetChecklistBtn">Reset Checklist</button>
          <button class="btn btn-ghost checklist-btn-incomplete${taskFilter === 'incomplete' ? ' active' : ''}" id="showIncompleteTasksBtn" aria-pressed="${taskFilter === 'incomplete' ? 'true' : 'false'}">Show Incomplete Tasks</button>
          <button class="btn btn-ghost checklist-btn-completed${taskFilter === 'completed' ? ' active' : ''}" id="showCompletedTasksBtn" aria-pressed="${taskFilter === 'completed' ? 'true' : 'false'}">Show Completed Tasks</button>
        </div>
        <div class="checklist-head-right">
          <span class="badge" style="border-color:rgba(16,185,129,.4);color:var(--green)">${completedItems.length} / ${totalItems} completed</span>
        </div>
      </div>
      <div class="checklist-list">
        ${phases.map((phase) => {
          const expanded = state.ui.openPhases.includes(phase.id);
          const completed = phase.items.filter((item) => completedItems.includes(item.id)).length;
          const progress = getPhaseProgress(phase, completedItems);
          return `
            <div class="accordion-item phase-${phase.id}" id="phase-${machine.id}-${phase.id}">
              <button class="accordion-head" data-phase-toggle="${phase.id}">
                <span class="phase-title">
                  <span class="phase-icon">${PHASE_EMOJI[phase.id] || '🔧'}</span>
                  <span class="phase-name">${phase.name}</span>
                  ${phase.optional ? '<span class="badge">Optional</span>' : ''}
                </span>
                <div class="phase-progress">
                  <span class="small mono">${completed}/${phase.items.length}</span>
                  <div class="progress-bar" style="width:110px"><div class="progress-fill" style="width:${progress}%"></div></div>
                </div>
              </button>
              <div class="accordion-body" style="display:${expanded ? 'block' : 'none'}">
                ${phase.items.map((item) => {
                  const done = completedItems.includes(item.id);
                  const evidence = machine.item_evidence?.[item.id] || [];
                  return `
                    <div class="check-item" id="task-${machine.id}-${item.id}">
                      <div class="check-line">
                        <input type="checkbox" data-check-item="${item.id}" ${done ? 'checked' : ''}>
                        <span class="${done ? 'line' : ''}" style="user-select:text;cursor:default;">${item.name}</span>
                      </div>
                      ${item.description ? `<div class="small dim" style="margin:.3rem 0 .15rem 1.75rem;line-height:1.45">${item.description}</div>` : ''}
                      ${item.commands ? item.commands.map((c, ci) => `
                        <div class="cmd-sub-desc cmd-sub-desc-main">${c.desc}</div>
                        ${c.entries.map((e, ei) => `
                          ${e.subdesc ? `<div class="cmd-sub-desc cmd-sub-desc-sub">${e.subdesc}</div>` : ''}
                          <div class="cmd-block mt-2">
                            <pre>${substituteTargetIp(e.cmd, machine.ip).replace(/</g, '&lt;')}</pre>
                            <button class="cmd-copy" data-copy-raw-idx="${item.id}__${ci}__${ei}">Copy</button>
                          </div>
                        `).join('')}
                      `).join('') : item.command ? `
                        <div class="cmd-block mt-2 text-xs">
                          <pre>${substituteTargetIp(item.command, machine.ip).replace(/</g, '&lt;')}</pre>
                          <button class="cmd-copy" data-copy-cmd="${item.id}">Copy</button>
                        </div>
                      ` : ''}
                      <div class="evidence-block">
                        <div class="small dim">Evidence</div>
                        <input type="file" accept="image/*" multiple data-evidence-upload="${item.id}" style="display:none">
                        <div class="evidence-dropzone" data-evidence-drop="${item.id}" tabindex="0">Drop screenshots here or click and press Ctrl+V to paste</div>
                        ${evidence.length ? `
                          <div class="evidence-list">
                            ${evidence.map((file) => `
                              <div class="evidence-row">
                                <button class="btn btn-ghost evidence-open" data-open-evidence="${file.id}" type="button">${file.name}</button>
                                <div class="evidence-actions">
                                  <button class="icon-btn" data-rename-evidence="${file.id}" data-item-id="${item.id}" type="button" title="Rename">Rename</button>
                                  <button class="icon-btn" data-delete-evidence="${file.id}" data-item-id="${item.id}" type="button" title="Delete">Delete</button>
                                </div>
                              </div>
                            `).join('')}
                          </div>
                        ` : ''}
                      </div>
                    </div>
                  `;
                }).join('')}
              </div>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}

/** Render the credentials table tab with an inline add form for a machine. */
function renderMachineCredentialsTab(machine) {
  const credentials = machineCredentials(machine.id);

  return `
    <div class="mt-4">
      <div class="header-row" style="margin-bottom:.6rem">
        <h3 class="subhead">Machine Credentials</h3>
        <button class="btn btn-primary" id="openMachineCredForm">Add</button>
      </div>
      ${state.ui.showAddMachineCred ? `
        <div class="inline-form card">
          <div class="split">
            <label>Username *<input id="mcUsername"></label>
            <label>Service<input id="mcService" placeholder="SSH"></label>
          </div>
          <label>Password / Hash<input id="mcPassword"></label>
          <label>Type
            <select id="mcType">
              ${credTypeOptionsHtml()}
            </select>
          </label>
          <div class="modal-actions">
            <button class="btn btn-ghost" id="cancelMachineCredForm">Cancel</button>
            <button class="btn btn-primary" id="submitMachineCredForm">Add Credential</button>
          </div>
        </div>
      ` : ''}
      ${!credentials.length ? '<p class="small dim" style="padding:1rem;text-align:center">No credentials found yet</p>' : `
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Username</th><th>Password/Hash</th><th>Type</th><th>Service</th><th>Time</th><th>Actions</th></tr>
            </thead>
            <tbody>
              ${credentials.map((credential) => {
                const shown = state.reveal[credential.id];
                return `
                  <tr>
                    <td class="mono">${credential.username}</td>
                    <td class="mono" style="color:var(--muted)">${shown ? credential.password : '••••••••'}</td>
                    <td><span class="badge">${credential.cred_type}</span></td>
                    <td>${credential.service || '-'}</td>
                    <td class="small mono dim">${formatTime(credential.created_at)}</td>
                    <td>
                      <div class="actions">
                        <button class="icon-btn" data-machine-cred-action="reveal" data-id="${credential.id}" title="${shown ? 'Hide' : 'Reveal'}">${shown ? '🙈' : '👁'}</button>
                        <button class="icon-btn" data-machine-cred-action="copy" data-id="${credential.id}" title="Copy">⧉</button>
                        <button class="icon-btn" data-machine-cred-action="edit" data-id="${credential.id}" title="Edit">✎</button>
                        <button class="icon-btn" data-machine-cred-action="delete" data-id="${credential.id}" title="Delete">🗑</button>
                      </div>
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      `}
    </div>
  `;
}

/**
 * Recursively build finding cards with parent→child nesting.
 * @param {Array} allFindings - All findings for the machine
 * @param {string|null} parentId - Parent finding ID (null for root)
 * @param {number} depth - Nesting depth for visual indentation
 */
function buildFindingCards(allFindings, parentId, depth) {
  const children = allFindings.filter(f => (f.parent_id || null) === (parentId || null));
  return children.map(finding => {
    const parentFinding = depth === 0 ? null : allFindings.find(f => f.id === finding.parent_id);
    const isChild = depth > 0;
    return `
      <div class="finding-card${isChild ? ' finding-child' : ''}">
        <div class="finding-main">
          ${isChild && parentFinding ? `<div class="finding-parent-label">↳ child of <em>${parentFinding.title}</em></div>` : ''}
          <div class="finding-head">
            <span class="sev-badge ${severityClass[finding.severity] || 'severity-info'}">${finding.severity.toUpperCase()}</span>
            <span>${finding.title}</span>
            <span class="badge">${finding.phase}</span>
          </div>
          ${finding.description ? `<p class="small" style="margin-top:.35rem">${finding.description}</p>` : ''}
          ${(finding.evidence || []).length ? `
            <div class="evidence-list" style="margin-top:.35rem">
              ${(finding.evidence || []).map((file) => `
                <div class="evidence-row">
                  <button class="btn btn-ghost evidence-open" data-open-finding-evidence="${file.id}" type="button">${file.name}</button>
                  <button class="icon-btn" data-rename-finding-evidence="${file.id}" data-finding-id="${finding.id}" title="Rename">✎</button>
                  <button class="icon-btn" data-delete-finding-evidence="${file.id}" data-finding-id="${finding.id}" title="Delete">🗑</button>
                </div>
              `).join('')}
            </div>
          ` : ''}
          <p class="small mono dim" style="margin-top:.35rem">${formatDate(finding.created_at)}</p>
        </div>
        <div class="finding-actions">
          <button class="icon-btn" data-edit-finding="${finding.id}" title="Edit">✎</button>
          <button class="icon-btn" data-delete-finding="${finding.id}" title="Delete">🗑</button>
        </div>
      </div>
      ${buildFindingCards(allFindings, finding.id, depth + 1)}
    `;
  }).join('');
}

/** Render the findings list tab with inline add form and nested finding cards. */
function renderFindingsTab(machine) {
  const findings = machineFindings(machine.id);
  const machinePhases = checklistPhaseCatalogForMachine(machine);

  return `
    <div class="mt-4">
      <div class="header-row" style="margin-bottom:.6rem">
        <h3 class="subhead">Findings</h3>
        <button class="btn btn-primary" id="openFindingForm">Add</button>
      </div>
      ${state.ui.showAddFinding ? `
        <div class="inline-form card">
          <label>Title *<input id="findingTitle" placeholder="Apache 2.4.49 Path Traversal"></label>
          <label>Description<textarea id="findingDescription" rows="24" style="width:100%;margin-top:.4rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem"></textarea></label>
          <div class="split">
            <label>Severity
              <select id="findingSeverity">
                ${severityOptionsHtml('high')}
              </select>
            </label>
            <label>Phase
              <select id="findingPhase">${phaseOptionsHtml(machinePhases)}</select>
            </label>
          </div>
          <label>Parent Finding
            <select id="findingParentId">
              <option value="">Root Level (no parent)</option>
              ${parentFindingOptionsHtml(machine.id, machinePhases[0]?.id || '', new Set(), null, machine)}
            </select>
          </label>
          <input id="findingEvidence" type="file" accept="image/*" multiple style="display:none">
          <div class="evidence-dropzone" id="findingEvidenceDrop" tabindex="0">Drop screenshots here or click and press Ctrl+V to paste</div>
          <div class="evidence-list" id="findingEvidenceList"></div>
          <div class="modal-actions">
            <button class="btn btn-ghost" id="cancelFindingForm">Cancel</button>
            <button class="btn btn-primary" id="submitFindingForm">Add Finding</button>
          </div>
        </div>
      ` : ''}
      ${!findings.length ? '<p class="small dim" style="padding:1rem;text-align:center">No findings documented yet</p>' : `
        <div class="finding-list">
          ${buildFindingCards(findings, null, 0)}
        </div>
      `}
    </div>
  `;
}

/* ═══════════════════════════════════════════════════════════════════════════
   Pentest Notes Workspace (phase-based notes with rich editor)
   ═══════════════════════════════════════════════════════════════════════════ */

/** Get the phase note content for a machine */
function getPhaseNote(machine, phaseId) {
  return (machine.phase_notes || {})[phaseId] || '';
}

/** Set the phase note content for a machine */
function setPhaseNote(machine, phaseId, content) {
  machine.phase_notes = machine.phase_notes || {};
  machine.phase_notes[phaseId] = content;
}

/** Default H1 headers injected when a phase note is first loaded empty */
const DEFAULT_PHASE_HEADERS = {
  recon:             ['Port Enumeration', 'Web Enumeration'],
  exploitation:      ['Public Exploits', 'Exploitation Attacks'],
  post_exploitation: ['Post-Enumeration', 'Privilege Escalation'],
};

/**
 * If the phase note is empty, populate it with default H1 headers.
 * Returns the (possibly new) note content.
 */
function ensureDefaultHeaders(machine, phaseId) {
  const existing = getPhaseNote(machine, phaseId);
  if (existing.replace(/<[^>]*>/g, '').trim()) return existing;
  const headers = DEFAULT_PHASE_HEADERS[phaseId];
  if (!headers) return existing;
  const html = headers.map(h => `<h1>${escapeHtml(h)}</h1><p><br></p>`).join('');
  setPhaseNote(machine, phaseId, html);
  persistSoon();
  return html;
}

/**
 * When a port is toggled ON, inject a ## Port XX header under
 * the "Port Enumeration" H1 in the recon phase note (if not already present).
 */
function injectPortHeader(machine, port) {
  let html = getPhaseNote(machine, 'recon');
  /* Parse into a temporary DOM */
  const tmp = document.createElement('div');
  tmp.innerHTML = html;
  /* Check if an H2 "Port <port>" already exists */
  const headings = tmp.querySelectorAll('h2');
  for (const h of headings) {
    if (h.textContent.trim() === `Port ${port}`) return;
  }
  /* Find the "Port Enumeration" H1 */
  const h1s = tmp.querySelectorAll('h1');
  let portEnumH1 = null;
  for (const h of h1s) {
    if (h.textContent.trim() === 'Port Enumeration') { portEnumH1 = h; break; }
  }
  if (!portEnumH1) return;
  /* Find the insertion point: just before the next H1 (or end of content) */
  let insertBefore = null;
  let sibling = portEnumH1.nextElementSibling;
  while (sibling) {
    if (sibling.tagName === 'H1') { insertBefore = sibling; break; }
    sibling = sibling.nextElementSibling;
  }
  /* Build the new H2 + empty paragraph */
  const newH2 = document.createElement('h2');
  newH2.textContent = `Port ${port}`;
  const newP = document.createElement('p');
  newP.innerHTML = '<br>';
  if (insertBefore) {
    tmp.insertBefore(newP, insertBefore);
    tmp.insertBefore(newH2, newP);
  } else {
    tmp.appendChild(newH2);
    tmp.appendChild(newP);
  }
  setPhaseNote(machine, 'recon', tmp.innerHTML);
  persistSoon();
}

/** Extract a nested TOC from phase note HTML content */
function extractHeadingToc(htmlContent) {
  if (!htmlContent) return [];
  const tmp = document.createElement('div');
  tmp.innerHTML = htmlContent;
  const headings = tmp.querySelectorAll('h1, h2, h3');
  const items = [];
  headings.forEach((h, i) => {
    const level = parseInt(h.tagName[1], 10);
    const text = h.textContent.trim();
    if (text) items.push({ level, text, index: i });
  });
  return items;
}

/** Build the phase list sidebar HTML */
function buildPhaseListHtml(machine) {
  const phases = checklistPhaseCatalogForMachine(machine);
  const activeId = state.ui.activeNoteId;
  return phases.map(phase => {
    const emoji = PHASE_EMOJI[phase.id] || '🔧';
    const hasContent = !!(machine.phase_notes || {})[phase.id];
    const isActive = phase.id === activeId;
    let tocHtml = '';
    if (isActive) {
      const toc = extractHeadingToc(getPhaseNote(machine, phase.id));
      if (toc.length) {
        tocHtml = '<div class="toc-list">' + toc.map(h =>
          `<button class="toc-item toc-level-${h.level}" data-toc-index="${h.index}" type="button">${escapeHtml(h.text)}</button>`
        ).join('') + '</div>';
      }
    }
    return `
      <button class="note-tree-item${isActive ? ' active' : ''}" data-phase-note="${phase.id}" type="button">
        <span class="note-icon">${emoji}</span>
        <span class="note-label">${escapeHtml(phase.name)}</span>
        ${hasContent ? '<span class="note-has-content">●</span>' : ''}
      </button>
      ${tocHtml}
    `;
  }).join('');
}

/** Render the full notes workspace (phase sidebar + editor) */
function renderNotesWorkspace(machine) {
  const phases = checklistPhaseCatalogForMachine(machine);
  const activePhaseId = state.ui.activeNoteId;
  const activePhase = activePhaseId ? phases.find(p => p.id === activePhaseId) : null;
  const activeContent = activePhase ? ensureDefaultHeaders(machine, activePhase.id) : '';
  const reconPorts = getReconPortOptions();
  const selectedPorts = machine.selected_ports || [];

  return `
    <div class="port-filter-wrap">
      <div class="port-filter-header">
        <span class="port-filter-icon">&#x1F6AA;</span>
        <span class="port-filter-label">RECON PORTS</span>
        <span class="port-filter-line"></span>
      </div>
      <div class="port-filter-card">
        <div class="port-filter-list">
          ${reconPorts.length ? `
            <button class="port-chip${!selectedPorts.length ? ' active' : ''}" data-port-select="__all__" type="button">All</button>
            ${reconPorts.map(p => `<button class="port-chip${selectedPorts.includes(p) ? ' active' : ''}" data-port-select="${p}" type="button">${p}</button>`).join('')}
          ` : '<span class="small dim">No ports discovered yet</span>'}
        </div>
      </div>
    </div>
    <div class="notes-workspace">
      <div class="notes-editor">
        ${activePhase ? `
          <div class="notes-editor-header">
            <div class="notes-editor-title">
              <span>${PHASE_EMOJI[activePhase.id] || '🔧'} ${escapeHtml(activePhase.name)}</span>
            </div>
          </div>
          <div class="notes-toolbar">
            <button data-fmt="bold" title="Bold (Ctrl+B)"><b>B</b></button>
            <button data-fmt="italic" title="Italic (Ctrl+I)"><i>I</i></button>
            <button data-fmt="underline" title="Underline (Ctrl+U)"><u>U</u></button>
            <button data-fmt="strikeThrough" title="Strikethrough"><s>S</s></button>
            <span class="tb-sep"></span>
            <button data-fmt="formatBlock" data-val="H1" title="Heading 1">H1</button>
            <button data-fmt="formatBlock" data-val="H2" title="Heading 2">H2</button>
            <button data-fmt="formatBlock" data-val="H3" title="Heading 3">H3</button>
            <span class="tb-sep"></span>
            <button data-fmt="insertUnorderedList" title="Bullet list">• List</button>
            <button data-fmt="insertOrderedList" title="Numbered list">1. List</button>
            <span class="tb-sep"></span>
            <button data-fmt="formatBlock" data-val="PRE" title="Code block">&lt;/&gt;</button>
            <button id="notesInsertCollapsible" title="Collapsible code block">▶ &lt;/&gt;</button>
            <button data-fmt="formatBlock" data-val="BLOCKQUOTE" title="Blockquote">❝</button>
            <button data-fmt="insertHorizontalRule" title="Horizontal rule">―</button>
            <span class="tb-sep"></span>
            <button id="notesInsertLink" title="Insert link">🔗</button>
          </div>
          <div class="notes-editor-body" contenteditable="true" id="notesEditorBody" spellcheck="true" data-phase-id="${activePhase.id}">${activeContent}</div>
        ` : `
          <div class="notes-empty-state">
            <span class="notes-empty-icon">📝</span>
            <div>Select a phase to write notes</div>
            <div class="small dim">Paste screenshots directly with Ctrl+V</div>
          </div>
        `}
      </div>
    </div>
  `;
}

/** Wire event listeners for the notes workspace */
function wireNotesWorkspace(machine) {
  /* --- Select phase --- */
  document.querySelectorAll('[data-phase-note]').forEach(btn => {
    btn.addEventListener('click', () => {
      const phaseId = btn.dataset.phaseNote;
      saveActiveNoteContent(machine);
      state.ui.activeNoteId = phaseId;
      persist();
      mount();
    });
  });

  /* --- Rich text editor --- */
  const editorBody = document.getElementById('notesEditorBody');
  if (editorBody) {
    /* ── Inject delete buttons on block elements (pre, blockquote, hr, img) ── */
    function injectBlockDeleteButtons() {
      /* Remove existing delete buttons first */
      editorBody.querySelectorAll('.block-delete-btn').forEach(b => b.remove());
      editorBody.querySelectorAll('.hr-wrapper, .img-wrapper').forEach(w => {
        const child = w.firstElementChild;
        if (child) w.replaceWith(child);
        else w.remove();
      });

      /* Collapsible code blocks — delete button + toggle save */
      editorBody.querySelectorAll('details.collapsible-code').forEach(details => {
        /* Ensure summary is not editable */
        const summary = details.querySelector('summary');
        if (summary) summary.contentEditable = 'false';
        const btn = document.createElement('button');
        btn.className = 'block-delete-btn';
        btn.type = 'button';
        btn.contentEditable = 'false';
        btn.textContent = '✕';
        btn.title = 'Delete block';
        btn.addEventListener('mousedown', (e) => {
          e.preventDefault();
          e.stopPropagation();
          const p = document.createElement('p');
          p.innerHTML = '<br>';
          details.replaceWith(p);
          const range = document.createRange();
          range.selectNodeContents(p);
          range.collapse(true);
          const sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
          saveActiveNoteContent(machine);
          setTimeout(() => injectBlockDeleteButtons(), 0);
        });
        details.appendChild(btn);
        /* Save open/closed state on toggle */
        details.addEventListener('toggle', () => {
          saveActiveNoteContent(machine);
        });
      });

      /* Code blocks & blockquotes — append button inside */
      editorBody.querySelectorAll('pre:not(.collapsible-code pre), blockquote').forEach(block => {
        const btn = document.createElement('button');
        btn.className = 'block-delete-btn';
        btn.type = 'button';
        btn.contentEditable = 'false';
        btn.textContent = '✕';
        btn.title = 'Delete block';
        btn.addEventListener('mousedown', (e) => {
          e.preventDefault();
          e.stopPropagation();
          const p = document.createElement('p');
          p.innerHTML = '<br>';
          block.replaceWith(p);
          const range = document.createRange();
          range.selectNodeContents(p);
          range.collapse(true);
          const sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
          saveActiveNoteContent(machine);
          setTimeout(() => injectBlockDeleteButtons(), 0);
        });
        block.appendChild(btn);
      });

      /* Horizontal rules — wrap in a div so we can position the button */
      editorBody.querySelectorAll('hr').forEach(hr => {
        const wrapper = document.createElement('div');
        wrapper.className = 'hr-wrapper';
        wrapper.contentEditable = 'false';
        hr.replaceWith(wrapper);
        wrapper.appendChild(hr);
        const btn = document.createElement('button');
        btn.className = 'block-delete-btn';
        btn.type = 'button';
        btn.textContent = '✕';
        btn.title = 'Delete rule';
        btn.addEventListener('mousedown', (e) => {
          e.preventDefault();
          e.stopPropagation();
          const p = document.createElement('p');
          p.innerHTML = '<br>';
          wrapper.replaceWith(p);
          saveActiveNoteContent(machine);
          setTimeout(() => injectBlockDeleteButtons(), 0);
        });
        wrapper.appendChild(btn);
      });

      /* Images — wrap in a span so we can position the button */
      editorBody.querySelectorAll('img').forEach(img => {
        if (img.parentElement?.classList.contains('img-wrapper')) return;
        const wrapper = document.createElement('span');
        wrapper.className = 'img-wrapper';
        img.replaceWith(wrapper);
        wrapper.appendChild(img);
        const btn = document.createElement('button');
        btn.className = 'block-delete-btn';
        btn.type = 'button';
        btn.contentEditable = 'false';
        btn.textContent = '✕';
        btn.title = 'Delete image';
        btn.addEventListener('mousedown', (e) => {
          e.preventDefault();
          e.stopPropagation();
          const p = document.createElement('p');
          p.innerHTML = '<br>';
          wrapper.replaceWith(p);
          saveActiveNoteContent(machine);
          setTimeout(() => injectBlockDeleteButtons(), 0);
        });
        wrapper.appendChild(btn);
      });
    }

    injectBlockDeleteButtons();
    document.execCommand('defaultParagraphSeparator', false, 'p');

    /* Toolbar formatting buttons */
    document.querySelectorAll('[data-fmt]').forEach(btn => {
      btn.addEventListener('click', () => {
        const cmd = btn.dataset.fmt;
        const val = btn.dataset.val || null;
        document.execCommand(cmd, false, val);
        editorBody.focus();
        setTimeout(() => injectBlockDeleteButtons(), 0);
      });
    });

    /* Insert collapsible code block */
    document.getElementById('notesInsertCollapsible')?.addEventListener('click', () => {
      const details = document.createElement('details');
      details.className = 'collapsible-code';
      const summary = document.createElement('summary');
      summary.textContent = 'Code';
      summary.contentEditable = 'false';
      const pre = document.createElement('pre');
      pre.innerHTML = '<br>';
      details.appendChild(summary);
      details.appendChild(pre);
      const sel = window.getSelection();
      if (sel.rangeCount) {
        const range = sel.getRangeAt(0);
        range.deleteContents();
        range.insertNode(details);
        /* Place cursor inside the pre */
        const newRange = document.createRange();
        newRange.selectNodeContents(pre);
        newRange.collapse(true);
        sel.removeAllRanges();
        sel.addRange(newRange);
      }
      editorBody.focus();
      saveActiveNoteContent(machine);
      setTimeout(() => injectBlockDeleteButtons(), 0);
    });

    /* Insert link button */
    document.getElementById('notesInsertLink')?.addEventListener('click', () => {
      const url = prompt('Enter URL:');
      if (url) {
        document.execCommand('createLink', false, url);
        editorBody.focus();
      }
    });

    /* Paste handler — support pasting images directly */
    editorBody.addEventListener('paste', (e) => {
      const items = e.clipboardData?.items;
      if (!items) return;
      for (const item of items) {
        if (item.type.startsWith('image/')) {
          e.preventDefault();
          const blob = item.getAsFile();
          if (!blob) return;
          const reader = new FileReader();
          reader.onload = () => {
            const img = document.createElement('img');
            img.src = reader.result;
            img.alt = 'Screenshot';
            const sel = window.getSelection();
            if (sel.rangeCount) {
              const range = sel.getRangeAt(0);
              range.deleteContents();
              range.insertNode(img);
              range.setStartAfter(img);
              range.collapse(true);
              sel.removeAllRanges();
              sel.addRange(range);
            } else {
              editorBody.appendChild(img);
            }
            saveActiveNoteContent(machine);
            setTimeout(() => injectBlockDeleteButtons(), 0);
          };
          reader.readAsDataURL(blob);
          return;
        }
      }
    });

    /* ── Keyboard handling for code blocks ── */

    /* Detect # / ## / ### typed at the start of a line → convert to heading (Notion-style) */
    editorBody.addEventListener('input', () => {
      const sel = window.getSelection();
      if (!sel.rangeCount) return;
      const node = sel.anchorNode;
      if (!node || node.nodeType !== Node.TEXT_NODE) return;
      if (node.parentElement?.closest('pre, code')) return;
      const text = node.textContent;
      const match = text.match(/^(#{1,3})\s/);
      if (!match) return;
      const level = match[1].length;
      const tag = 'H' + level;
      const remaining = text.slice(match[0].length);
      const parentBlock = node.parentElement?.closest('p, div, h1, h2, h3, blockquote') || node.parentElement;
      if (parentBlock && parentBlock.tagName === tag) return; /* Already the correct heading */

      const heading = document.createElement(tag);
      heading.textContent = remaining || '\u200B';

      if (parentBlock && parentBlock !== editorBody) {
        parentBlock.replaceWith(heading);
      } else {
        node.remove();
        editorBody.appendChild(heading);
      }

      /* Place cursor at end of heading text */
      const range = document.createRange();
      range.selectNodeContents(heading);
      range.collapse(false);
      sel.removeAllRanges();
      sel.addRange(range);

      /* Update sidebar TOC */
      refreshSidebarToc(machine);
    });

    /* Detect `- ` or `* ` at the start of a line → unordered list */
    /* Detect `1. ` at the start of a line → ordered list */
    /* Detect `> ` at the start of a line → blockquote */
    /* Detect `---` → horizontal rule */
    editorBody.addEventListener('input', () => {
      const sel = window.getSelection();
      if (!sel.rangeCount) return;
      const node = sel.anchorNode;
      if (!node || node.nodeType !== Node.TEXT_NODE) return;
      const text = node.textContent;
      const parentBlock = node.parentElement?.closest('p, div, h1, h2, h3, li') || node.parentElement;
      /* Skip if already inside a list or blockquote */
      if (node.parentElement?.closest('li, blockquote, pre')) return;

      /* --- Unordered list: "- " or "* " --- */
      if (/^[-*]\s$/.test(text)) {
        const p = (parentBlock && parentBlock !== editorBody) ? parentBlock : null;
        if (p) { p.innerHTML = '<br>'; } else { node.textContent = ''; }
        document.execCommand('insertUnorderedList', false, null);
        return;
      }

      /* --- Ordered list: "1. " --- */
      if (/^1\.\s$/.test(text)) {
        const p = (parentBlock && parentBlock !== editorBody) ? parentBlock : null;
        if (p) { p.innerHTML = '<br>'; } else { node.textContent = ''; }
        document.execCommand('insertOrderedList', false, null);
        return;
      }

      /* --- Blockquote: "> " --- */
      if (/^>\s$/.test(text)) {
        const p = (parentBlock && parentBlock !== editorBody) ? parentBlock : null;
        if (p) { p.innerHTML = '<br>'; } else { node.textContent = ''; }
        document.execCommand('formatBlock', false, 'BLOCKQUOTE');
        setTimeout(() => injectBlockDeleteButtons(), 0);
        return;
      }

      /* --- Horizontal rule: "---" (with optional trailing space) --- */
      if (/^-{3,}\s?$/.test(text)) {
        const p = (parentBlock && parentBlock !== editorBody) ? parentBlock : null;
        if (p) p.remove(); else node.remove();
        document.execCommand('insertHorizontalRule', false, null);
        setTimeout(() => injectBlockDeleteButtons(), 0);
        return;
      }
    });

    /* Detect ``` typed inline and convert to a code block (Notion-style) */
    editorBody.addEventListener('input', (e) => {
      const sel = window.getSelection();
      if (!sel.rangeCount) return;
      const node = sel.anchorNode;
      if (!node || node.nodeType !== Node.TEXT_NODE) return;
      if (node.parentElement?.closest('pre')) return;
      const text = node.textContent;
      /* Match exactly "```" (optionally preceded only by whitespace at the start of the block) */
      const idx = text.indexOf('\`\`\`');
      if (idx === -1) return;
      const before = text.slice(0, idx).trim();
      if (before) return; /* Only trigger at the start of a line / block */

      e.preventDefault?.();
      const parentBlock = node.parentElement?.closest('p, div, h1, h2, h3, blockquote') || node.parentElement;

      /* Create the code block */
      const pre = document.createElement('pre');
      const code = document.createElement('code');
      code.textContent = text.slice(idx + 3).trim() || '';
      pre.appendChild(code);

      /* Create a paragraph after it so the cursor can escape */
      const after = document.createElement('p');
      after.innerHTML = '<br>';

      if (parentBlock && parentBlock !== editorBody) {
        parentBlock.replaceWith(pre, after);
      } else {
        /* Replace the text node directly */
        node.remove();
        editorBody.appendChild(pre);
        editorBody.appendChild(after);
      }

      /* Place cursor inside the code block */
      const range = document.createRange();
      range.selectNodeContents(code);
      range.collapse(code.textContent.length > 0 ? false : true);
      sel.removeAllRanges();
      sel.addRange(range);
      setTimeout(() => injectBlockDeleteButtons(), 0);
    });

    /* Detect `text` → inline code (Notion-style) */
    editorBody.addEventListener('input', () => {
      const sel = window.getSelection();
      if (!sel.rangeCount) return;
      const node = sel.anchorNode;
      if (!node || node.nodeType !== Node.TEXT_NODE) return;
      if (node.parentElement?.closest('pre, code')) return;
      const text = node.textContent;
      const match = text.match(/`([^`\n]+)`/);
      if (!match) return;
      const before = text.slice(0, match.index);
      const inner = match[1];
      const after = text.slice(match.index + match[0].length);
      const codeEl = document.createElement('code');
      codeEl.textContent = inner;
      const parent = node.parentNode;
      const frag = document.createDocumentFragment();
      if (before) frag.appendChild(document.createTextNode(before));
      frag.appendChild(codeEl);
      const afterNode = document.createTextNode(after || '\u00A0');
      frag.appendChild(afterNode);
      parent.replaceChild(frag, node);
      const range = document.createRange();
      range.setStart(afterNode, after ? 0 : 1);
      range.collapse(true);
      sel.removeAllRanges();
      sel.addRange(range);
    });

    /* ── Double-backtick shortcut: `` → insert collapsible code block ── */
    editorBody.addEventListener('keydown', (e) => {
      if (e.key !== '`') return;
      const sel = window.getSelection();
      if (!sel.rangeCount) return;
      const anchor = sel.anchorNode;
      if (!anchor || anchor.nodeType !== Node.TEXT_NODE) return;
      /* Check if the character right before the cursor is also a backtick */
      const offset = sel.getRangeAt(0).startOffset;
      const text = anchor.textContent || '';
      if (offset < 1 || text[offset - 1] !== '`') return;
      /* Already inside a code block — skip */
      if (anchor.parentElement?.closest('pre, details.collapsible-code')) return;
      e.preventDefault();
      /* Remove the first backtick */
      anchor.textContent = text.slice(0, offset - 1) + text.slice(offset);
      /* Remove the now-empty text node parent (e.g. <p>) if empty */
      const parentBlock = anchor.parentElement?.closest('p, div');
      /* Build the collapsible block */
      const details = document.createElement('details');
      details.className = 'collapsible-code';
      const summary = document.createElement('summary');
      summary.textContent = 'Code';
      summary.contentEditable = 'false';
      const pre = document.createElement('pre');
      pre.innerHTML = '<br>';
      details.appendChild(summary);
      details.appendChild(pre);
      if (parentBlock && !parentBlock.textContent.trim()) {
        parentBlock.replaceWith(details);
      } else {
        const range = sel.getRangeAt(0);
        range.insertNode(details);
      }
      /* Place cursor inside the pre */
      const newRange = document.createRange();
      newRange.selectNodeContents(pre);
      newRange.collapse(true);
      sel.removeAllRanges();
      sel.addRange(newRange);
      details.setAttribute('open', '');
      saveActiveNoteContent(machine);
      setTimeout(() => injectBlockDeleteButtons(), 0);
    });

    /* Handle Enter / Backspace / Arrow keys inside code blocks */
    editorBody.addEventListener('keydown', (e) => {
      const sel = window.getSelection();
      if (!sel.rangeCount) return;
      const anchor = sel.anchorNode;
      const pre = anchor?.nodeType === Node.TEXT_NODE
        ? anchor.parentElement?.closest('pre')
        : anchor?.closest?.('pre');
      if (!pre || !editorBody.contains(pre)) return;

      /* ── Enter in code block: double-Enter at end to escape (Notion-style) ── */
      if (e.key === 'Enter') {
        const code = pre.querySelector('code') || pre;
        const txt = code.textContent || '';
        /* Check if cursor is at the absolute end of the code content */
        const curRange = sel.getRangeAt(0);
        const afterRange = document.createRange();
        afterRange.selectNodeContents(code);
        afterRange.setStart(curRange.endContainer, curRange.endOffset);
        const cursorAtEnd = afterRange.toString().length === 0;
        /* If cursor is at the end and text already ends with \n,
           the user just pressed Enter on a blank line → escape out */
        if (cursorAtEnd && txt.endsWith('\n')) {
          e.preventDefault();
          code.textContent = txt.replace(/\n+$/, '');
          let next = pre.nextElementSibling;
          if (!next || (next.tagName !== 'P' && next.tagName !== 'DIV')) {
            next = document.createElement('p');
            next.innerHTML = '<br>';
            pre.after(next);
          }
          const newRange = document.createRange();
          newRange.selectNodeContents(next);
          newRange.collapse(true);
          sel.removeAllRanges();
          sel.addRange(newRange);
          return;
        }
        /* Normal Enter inside code block → insert a plain newline */
        e.preventDefault();
        document.execCommand('insertText', false, '\n');
        return;
      }

      /* ── Backspace on empty code block → delete it ── */
      if (e.key === 'Backspace') {
        const code = pre.querySelector('code') || pre;
        const txt = code.textContent || '';
        if (txt === '' || txt === '\n') {
          e.preventDefault();
          let next = pre.nextElementSibling;
          let prev = pre.previousElementSibling;
          const target = prev || next;
          if (!target) {
            const p = document.createElement('p');
            p.innerHTML = '<br>';
            pre.replaceWith(p);
            const range = document.createRange();
            range.selectNodeContents(p);
            range.collapse(true);
            sel.removeAllRanges();
            sel.addRange(range);
          } else {
            pre.remove();
            const range = document.createRange();
            range.selectNodeContents(target);
            range.collapse(target === prev ? false : true);
            sel.removeAllRanges();
            sel.addRange(range);
          }
          return;
        }
      }

      /* ── ArrowDown at the end of the last line → escape below ── */
      if (e.key === 'ArrowDown') {
        const code = pre.querySelector('code') || pre;
        const txt = code.textContent || '';
        const isAtEnd = sel.anchorOffset >= (anchor.textContent || '').length;
        if (isAtEnd) {
          let next = pre.nextElementSibling;
          if (!next) {
            next = document.createElement('p');
            next.innerHTML = '<br>';
            pre.after(next);
          }
          e.preventDefault();
          const range = document.createRange();
          range.selectNodeContents(next);
          range.collapse(true);
          sel.removeAllRanges();
          sel.addRange(range);
        }
      }

      /* ── ArrowUp at the start of the first line → escape above ── */
      if (e.key === 'ArrowUp') {
        if (sel.anchorOffset === 0) {
          let prev = pre.previousElementSibling;
          if (!prev) {
            prev = document.createElement('p');
            prev.innerHTML = '<br>';
            pre.before(prev);
          }
          e.preventDefault();
          const range = document.createRange();
          range.selectNodeContents(prev);
          range.collapse(false);
          sel.removeAllRanges();
          sel.addRange(range);
        }
      }

      /* ── Tab in code block → insert spaces ── */
      if (e.key === 'Tab') {
        e.preventDefault();
        document.execCommand('insertText', false, '    ');
      }
    });

    /* ── General keydown: heading Enter, Tab, Ctrl shortcuts ── */
    editorBody.addEventListener('keydown', (e) => {
      const sel = window.getSelection();
      if (!sel.rangeCount) return;
      const anchor = sel.anchorNode;
      /* Skip if inside a code block (handled by the handler above) */
      const inPre = anchor?.nodeType === Node.TEXT_NODE
        ? anchor.parentElement?.closest('pre')
        : anchor?.closest?.('pre');
      if (inPre && editorBody.contains(inPre)) return;

      /* ── Enter on empty list item → exit list (Notion-style) ── */
      if (e.key === 'Enter' && !e.shiftKey) {
        const li = anchor?.nodeType === Node.TEXT_NODE
          ? anchor.parentElement?.closest('li')
          : anchor?.closest?.('li');
        if (li && editorBody.contains(li)) {
          const liText = li.textContent || '';
          if (!liText.trim()) {
            e.preventDefault();
            const list = li.closest('ul, ol');
            if (list) {
              const itemsAfter = [];
              let sib = li.nextElementSibling;
              while (sib) { itemsAfter.push(sib); sib = sib.nextElementSibling; }
              li.remove();
              const p = document.createElement('p');
              p.innerHTML = '<br>';
              if (itemsAfter.length) {
                const newList = document.createElement(list.tagName);
                itemsAfter.forEach(item => newList.appendChild(item));
                list.after(p, newList);
              } else {
                list.after(p);
              }
              if (!list.children.length) list.remove();
              const range = document.createRange();
              range.selectNodeContents(p);
              range.collapse(true);
              sel.removeAllRanges();
              sel.addRange(range);
              return;
            }
          }
        }
      }

      /* ── Enter in a heading → split into heading + paragraph (Notion-style) ── */
      if (e.key === 'Enter' && !e.shiftKey) {
        const heading = anchor?.nodeType === Node.TEXT_NODE
          ? anchor.parentElement?.closest('h1, h2, h3')
          : anchor?.closest?.('h1, h2, h3');
        if (heading && editorBody.contains(heading)) {
          e.preventDefault();
          const range = sel.getRangeAt(0);
          /* Check if cursor is at the very start */
          const beforeCursor = document.createRange();
          beforeCursor.selectNodeContents(heading);
          beforeCursor.setEnd(range.startContainer, range.startOffset);
          if (beforeCursor.toString().length === 0) {
            /* Insert blank paragraph above, keep cursor in heading */
            const blankP = document.createElement('p');
            blankP.innerHTML = '<br>';
            heading.before(blankP);
            return;
          }
          /* Extract tail content into a new paragraph */
          const tailRange = range.cloneRange();
          tailRange.selectNodeContents(heading);
          tailRange.setStart(range.startContainer, range.startOffset);
          const tail = tailRange.extractContents();
          const p = document.createElement('p');
          if (tail.textContent.trim()) {
            p.appendChild(tail);
          } else {
            p.innerHTML = '<br>';
          }
          heading.after(p);
          const newRange = document.createRange();
          newRange.selectNodeContents(p);
          newRange.collapse(true);
          sel.removeAllRanges();
          sel.addRange(newRange);
          refreshSidebarToc(machine);
          return;
        }
      }

      /* ── Enter in a blockquote → if line is empty, escape out ── */
      if (e.key === 'Enter' && !e.shiftKey) {
        const bq = anchor?.nodeType === Node.TEXT_NODE
          ? anchor.parentElement?.closest('blockquote')
          : anchor?.closest?.('blockquote');
        if (bq && editorBody.contains(bq)) {
          const text = anchor?.textContent || '';
          if (!text.trim() || text === '\n') {
            e.preventDefault();
            const p = document.createElement('p');
            p.innerHTML = '<br>';
            bq.after(p);
            /* If the blockquote only had the empty line, remove it */
            if (!bq.textContent.trim()) bq.remove();
            const newRange = document.createRange();
            newRange.selectNodeContents(p);
            newRange.collapse(true);
            sel.removeAllRanges();
            sel.addRange(newRange);
            return;
          }
        }
      }

      /* ── Backspace at start of heading → convert to paragraph ── */
      if (e.key === 'Backspace') {
        const heading = anchor?.nodeType === Node.TEXT_NODE
          ? anchor.parentElement?.closest('h1, h2, h3')
          : anchor?.closest?.('h1, h2, h3');
        if (heading && editorBody.contains(heading)) {
          const range = sel.getRangeAt(0);
          const beforeRange = document.createRange();
          beforeRange.selectNodeContents(heading);
          beforeRange.setEnd(range.startContainer, range.startOffset);
          if (beforeRange.toString().length === 0) {
            e.preventDefault();
            const p = document.createElement('p');
            p.innerHTML = heading.innerHTML || '<br>';
            heading.replaceWith(p);
            const newRange = document.createRange();
            newRange.selectNodeContents(p);
            newRange.collapse(true);
            sel.removeAllRanges();
            sel.addRange(newRange);
            refreshSidebarToc(machine);
            return;
          }
        }
        /* ── Backspace at start of blockquote → unwrap to paragraph ── */
        const bq = anchor?.nodeType === Node.TEXT_NODE
          ? anchor.parentElement?.closest('blockquote')
          : anchor?.closest?.('blockquote');
        if (bq && editorBody.contains(bq)) {
          const range = sel.getRangeAt(0);
          const beforeRange = document.createRange();
          beforeRange.selectNodeContents(bq);
          beforeRange.setEnd(range.startContainer, range.startOffset);
          if (beforeRange.toString().length === 0) {
            e.preventDefault();
            const p = document.createElement('p');
            p.innerHTML = bq.innerHTML || '<br>';
            bq.replaceWith(p);
            const newRange = document.createRange();
            newRange.selectNodeContents(p);
            newRange.collapse(true);
            sel.removeAllRanges();
            sel.addRange(newRange);
            return;
          }
        }
      }

      /* ── Tab / Shift+Tab: indent / outdent ── */
      if (e.key === 'Tab') {
        e.preventDefault();
        if (e.shiftKey) {
          document.execCommand('outdent', false, null);
        } else {
          /* If inside a list, indent the list item; otherwise insert spaces */
          const li = anchor?.nodeType === Node.TEXT_NODE
            ? anchor.parentElement?.closest('li')
            : anchor?.closest?.('li');
          if (li) {
            document.execCommand('indent', false, null);
          } else {
            document.execCommand('insertText', false, '    ');
          }
        }
        return;
      }

      /* ── Ctrl+1/2/3: heading shortcuts ── */
      if (e.ctrlKey && !e.shiftKey && !e.altKey) {
        if (e.key === '1' || e.key === '2' || e.key === '3') {
          e.preventDefault();
          const tag = 'H' + e.key;
          /* Toggle: if already the same heading, revert to paragraph */
          const curBlock = anchor?.nodeType === Node.TEXT_NODE
            ? anchor.parentElement?.closest('h1, h2, h3, p, div')
            : anchor?.closest?.('h1, h2, h3, p, div');
          if (curBlock && curBlock.tagName === tag) {
            document.execCommand('formatBlock', false, 'P');
          } else {
            document.execCommand('formatBlock', false, tag);
          }
          refreshSidebarToc(machine);
          return;
        }
        /* ── Ctrl+0: clear block formatting (back to paragraph) ── */
        if (e.key === '0') {
          e.preventDefault();
          document.execCommand('formatBlock', false, 'P');
          refreshSidebarToc(machine);
          return;
        }
        /* ── Ctrl+Shift is handled below ── */
      }

      /* ── Ctrl+Shift+X: clear all formatting ── */
      if (e.ctrlKey && e.shiftKey && (e.key === 'x' || e.key === 'X')) {
        e.preventDefault();
        document.execCommand('removeFormat', false, null);
        document.execCommand('formatBlock', false, 'P');
        refreshSidebarToc(machine);
        return;
      }
    });

    /* ── Image double-click → zoom modal ── */
    editorBody.addEventListener('dblclick', (e) => {
      const img = e.target.closest('img');
      if (!img) return;
      e.preventDefault();
      const modal = document.getElementById('imageZoomModal');
      const zoomImg = document.getElementById('imageZoomImg');
      if (!modal || !zoomImg) return;
      zoomImg.src = img.src;
      modal.showModal();
    });

    /* Auto-save on input (debounced) */
    let noteSaveTimer;
    let tocTimer;
    let mmTimer;
    editorBody.addEventListener('input', () => {
      clearTimeout(noteSaveTimer);
      noteSaveTimer = setTimeout(() => {
        saveActiveNoteContent(machine);
      }, 500);
      clearTimeout(tocTimer);
      tocTimer = setTimeout(() => {
        refreshSidebarToc(machine);
      }, 300);
      /* Live-update mind map when headings change */
      clearTimeout(mmTimer);
      mmTimer = setTimeout(() => {
        refreshMindMapInPlace(machine);
      }, 600);
    });

    /* Save on blur */
    editorBody.addEventListener('blur', () => {
      saveActiveNoteContent(machine);
      refreshMindMapInPlace(machine);
    });

    /* Wire initial TOC clicks (for pre-existing headings) */
    wireTocClicks(editorBody);
  }

  /* --- Port selection (informational, not tied to filtering) --- */
  document.querySelectorAll('[data-port-select]').forEach(btn => {
    btn.addEventListener('click', () => {
      const port = btn.dataset.portSelect;
      if (port === '__all__') {
        machine.selected_ports = [];
      } else {
        const sel = new Set(machine.selected_ports || []);
        const wasSelected = sel.has(port);
        if (wasSelected) sel.delete(port); else sel.add(port);
        machine.selected_ports = Array.from(sel).sort((a, b) => Number(a) - Number(b));
        /* Inject H2 header under "Port Enumeration" when a port is toggled ON */
        if (!wasSelected) {
          /* Flush editor content first so injectPortHeader works on current data */
          saveActiveNoteContent(machine);
          ensureDefaultHeaders(machine, 'recon');
          injectPortHeader(machine, port);
          /* Sync editor DOM so mount()'s save doesn't overwrite the injection */
          const editorBody = document.getElementById('notesEditorBody');
          if (editorBody && editorBody.dataset.phaseId === 'recon') {
            editorBody.innerHTML = getPhaseNote(machine, 'recon');
          }
        }
      }
      persistSoon();
      mount();
    });
  });
}

/** Save the current editor content back to the active phase note */
function saveActiveNoteContent(machine) {
  const editorBody = document.getElementById('notesEditorBody');
  if (!editorBody) return;
  /* Use the phase ID stamped on the editor element, not state.ui.activeNoteId,
     because state may have already been updated to a new phase before mount()
     re-renders the DOM. */
  const phaseId = editorBody.dataset.phaseId;
  if (phaseId) {
    setPhaseNote(machine, phaseId, editorBody.innerHTML);
    persistSoon();
  }
}

/** Refresh just the sidebar TOC under the active phase (no full re-render) */
function refreshSidebarToc(machine) {
  const treeList = document.querySelector('.notes-tree-list');
  if (!treeList) return;
  const editorBody = document.getElementById('notesEditorBody');
  if (!editorBody) return;
  const phaseId = state.ui.activeNoteId;
  if (!phaseId) return;
  /* Remove existing TOC */
  treeList.querySelectorAll('.toc-list').forEach(el => el.remove());
  /* Extract headings from live editor content */
  const toc = extractHeadingToc(editorBody.innerHTML);
  if (!toc.length) return;
  /* Find the active phase button and insert TOC after it */
  const activeBtn = treeList.querySelector(`.note-tree-item[data-phase-note="${phaseId}"]`);
  if (!activeBtn) return;
  const tocDiv = document.createElement('div');
  tocDiv.className = 'toc-list';
  tocDiv.innerHTML = toc.map(h =>
    `<button class="toc-item toc-level-${h.level}" data-toc-index="${h.index}" type="button">${escapeHtml(h.text)}</button>`
  ).join('');
  activeBtn.after(tocDiv);
  /* Wire TOC click → scroll to heading */
  wireTocClicks(editorBody);
}

/** Wire TOC item clicks to scroll to the corresponding heading in the editor */
function wireTocClicks(editorBody) {
  document.querySelectorAll('.toc-item[data-toc-index]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const idx = parseInt(btn.dataset.tocIndex, 10);
      const headings = editorBody.querySelectorAll('h1, h2, h3');
      if (headings[idx]) {
        headings[idx].scrollIntoView({ behavior: 'smooth', block: 'center' });
        /* Place cursor in the heading */
        const sel = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(headings[idx]);
        range.collapse(false);
        sel.removeAllRanges();
        sel.addRange(range);
      }
    });
  });
}

/**
 * Render an inline credential panel below the mind map.
 * Shows up to MAX_VISIBLE credentials with reveal/hide toggle;
 * overflow triggers a link to the full credentials modal.
 */
function renderCredInlinePanel(machine) {
  const creds = machineCredentials(machine.id);
  const MAX_VISIBLE = 6;
  const overflow = creds.length > MAX_VISIBLE;
  return `
    <div class="mm-cred-panel mm-cred-panel--inline">
      <div class="mm-cred-panel-header">
        <span class="mm-cred-panel-icon">🔑</span>
        <span class="mm-cred-panel-label">CREDENTIALS</span>
        <span class="mm-cred-panel-count">${creds.length}</span>
        <button class="btn btn-ghost mm-cred-expand-btn" id="credPanelMaximize" title="View all credentials">⤢</button>
      </div>
      <div class="mm-cred-panel-body">
        ${!creds.length ? '<div class="mm-cred-empty">No credentials documented yet</div>' : creds.slice(0, MAX_VISIBLE).map(c => `
          <div class="mm-cred-row" data-mm-cred-edit="${c.id}" title="Click to edit">
            <div class="mm-cred-row-main">
              <span class="mm-cred-username">${c.username}</span>
              <span class="mm-cred-badge">${c.service || c.cred_type}</span>
            </div>
            <div class="mm-cred-row-pw">
              <span class="mm-cred-pw-val">${state.reveal[c.id] ? (c.password || '—') : '••••••'}</span>
              <button class="mm-cred-reveal-btn" data-mm-reveal-cred="${c.id}" title="${state.reveal[c.id] ? 'Hide' : 'Show'}">${state.reveal[c.id] ? '🙈' : '👁'}</button>
            </div>
          </div>
        `).join('')}
        ${overflow ? `<button class="btn btn-ghost mm-cred-overflow-btn" id="credPanelMaximize2">••• +${creds.length - MAX_VISIBLE} more — view all</button>` : ''}
      </div>
    </div>
  `;
}

/**
 * Render the machine mind map visualisation.
 *
 * Supported views:
 * • Default ("all" phase) — quadrant grid showing all phases with SVG
 *   leaf connectors for parent→child relationships.
 * • Single-phase — day-column layout grouping findings by creation date.
 * • Fullscreen — free-form draggable block workspace with SVG connectors.
 *
 * Also renders the phase filter bar, zoom controls, and unlinked credentials.
 */
function renderMachineMindMap(machine) {
  const isFullscreenView = mmFsMachineId === machine.id;
  const machinePhases = checklistPhaseCatalogForMachine(machine);
  const phaseLabel = (phase) => {
    if (phase.id === 'osint') return 'OSINT';
    if (phase.id === 'recon') return 'Enumeration';
    if (phase.id === 'post_exploitation') return 'Post-Exploit';
    return phase.name;
  };

  const PHASE_DEFS = [
    { id: 'all', label: 'Default', col: '#94a3b8' },
    ...machinePhases.map((phase) => ({
      id: phase.id,
      label: phaseLabel(phase),
      col: phaseColor(phase.id),
    })),
  ];

  const activePhaseRaw = state.ui.mmPhase || 'all';
  const activePhase = PHASE_DEFS.some((phaseDef) => phaseDef.id === activePhaseRaw) ? activePhaseRaw : 'all';

  const PHASE_ORDER = machinePhases.map((phase) => phase.id);

  const vpId     = 'mm-vp-'     + machine.id;
  const canvasId = 'mm-canvas-' + machine.id;

  const filterBar = `
    <div class="mm-phase-bar">
      <div class="mm-phase-tabs">
        ${PHASE_DEFS.map(f => `
          <button
            class="mm-phase-btn${activePhase === f.id ? ' mm-phase-btn--active' : ''}${f.id === 'all' ? ' mm-phase-btn--all' : ''}"
            data-mm-phase="${f.id}"
            ${f.col ? `style="--pcol:${f.col}"` : ''}
          >${f.label}</button>
        `).join('')}
      </div>
      <div class="mm-phase-actions">
        <button class="mm-zoom-btn" id="mm-zoom-reset-${machine.id}" title="Restart View">Restart View &#x21BA;</button>
        <button class="mm-zoom-btn mm-fs-btn" id="mm-fs-${machine.id}" title="Full-Screen">Full-Screen &#x26F6;</button>
      </div>
    </div>
  `;

  /* ── Extract heading tree for a phase ── */
  function getPhaseHeadingTree(phaseId) {
    const html = getPhaseNote(machine, phaseId);
    if (!html) return [];
    const toc = extractHeadingToc(html);
    /* Build a nested tree: h1 at root, h2 under last h1, h3 under last h2 */
    const tree = [];
    let lastH1 = null, lastH2 = null;
    toc.forEach(h => {
      const node = { level: h.level, text: h.text, index: h.index, children: [] };
      if (h.level === 1) {
        tree.push(node);
        lastH1 = node;
        lastH2 = null;
      } else if (h.level === 2) {
        if (lastH1) { lastH1.children.push(node); }
        else { tree.push(node); }
        lastH2 = node;
      } else {
        if (lastH2) { lastH2.children.push(node); }
        else if (lastH1) { lastH1.children.push(node); }
        else { tree.push(node); }
      }
    });
    return tree;
  }

  /* ── Render heading node recursively ── */
  function renderHeadingNode(node, phaseId, col) {
    const levelClass = `mm-heading-level-${node.level}`;
    const childrenHtml = node.children.length ? `
      <div class="mm-heading-children">
        ${node.children.map(c => renderHeadingNode(c, phaseId, col)).join('')}
      </div>
    ` : '';
    return `
      <div class="mm-heading-row ${levelClass}">
        <button class="mm-heading-node" data-mm-heading-jump="${phaseId}" data-mm-heading-index="${node.index}" type="button" style="--node-phase-col:${col}">
          <span class="mm-heading-tag">H${node.level}</span>
          <span class="mm-heading-text">${escapeHtml(node.text)}</span>
        </button>
        ${childrenHtml}
      </div>
    `;
  }

  /* ── Render a phase block ── */
  function renderPhaseBlock(phaseId, col, name, leftPx, topPx) {
    const tree = getPhaseHeadingTree(phaseId);
    const headingCount = (function countAll(nodes) { return nodes.reduce((s, n) => s + 1 + countAll(n.children), 0); })(tree);
    return `
      <div class="mm-fs-block" data-mm-drag-block="${phaseId}"
           style="--phase-col:${col}; left:${leftPx}px; top:${topPx}px">
        <div class="mm-fs-block-header" data-mm-drag-handle>
          <span class="mm-phase-lane-dot" style="background:${col};box-shadow:0 0 7px ${col}99"></span>
          <span class="mm-fs-block-name">${name}</span>
          <span class="mm-phase-lane-count">${headingCount}</span>
        </div>
        <div class="mm-fs-block-body">
          ${!tree.length ? '<span class="mm-empty-hint">no notes yet</span>' :
            tree.map(n => renderHeadingNode(n, phaseId, col)).join('')}
        </div>
      </div>`;
  }

  const phaseName = (id) => {
    const def = PHASE_DEFS.find(d => d.id === id);
    if (def && def.label !== 'Default') return def.label;
    const p = machinePhases.find(ph => ph.id === id);
    return p ? p.name : id;
  };

  /* ── Check if any phase has headings ── */
  const anyHeadings = PHASE_ORDER.some(pid => getPhaseHeadingTree(pid).length > 0);

  let canvasContent;
  if (activePhase === 'all') {
    const fsBlocks = PHASE_ORDER.map((pid, i) => {
      const col  = phaseColor(pid);
      const name = phaseName(pid);
      return renderPhaseBlock(pid, col, name, i * 400, 40 + (i % 2) * 30);
    });

    canvasContent = `
      <div class="mm-fs-workspace">
        <svg class="mm-fs-connectors-svg" xmlns="http://www.w3.org/2000/svg"></svg>
        ${fsBlocks.join('')}
      </div>
    `;
  } else {
    const col   = phaseColor(activePhase);
    const name  = phaseName(activePhase);
    const tree  = getPhaseHeadingTree(activePhase);

    const phaseBody = !tree.length
      ? '<p class="small dim" style="margin:.75rem 0 .25rem">No headings in this phase yet. Add H1/H2/H3 headings to your notes.</p>'
      : `<div class="mm-single-leaves">${tree.map(n => renderHeadingNode(n, activePhase, col)).join('')}</div>`;

    canvasContent = `
      <div class="mm-single-phase" style="--phase-col:${col}">
        <div class="mm-phase-big-header" style="color:${col}">
          <span class="mm-phase-big-dot" style="background:${col};box-shadow:0 0 12px ${col}88"></span>
          ${name}
        </div>
        ${phaseBody}
      </div>
    `;
  }

  if (!anyHeadings && activePhase === 'all') {
    canvasContent = `
      <div class="mm-fs-workspace">
        <p class="small dim" style="padding:.75rem">Add H1/H2/H3 headings to your phase notes to populate the mind map.</p>
      </div>
    `;
  }

  return `
    <div class="machine-mindmap" id="mm-container-${machine.id}">
      ${filterBar}
      <div class="mm-viewport" id="${vpId}">
        <div class="mm-pan-canvas" id="${canvasId}">${canvasContent}</div>
      </div>
    </div>
  `;
}

/**
 * Render the full machine detail page:
 * • Machine header (IP, hostname, status, OS, progress bar)
 * • Mind map visualisation
 * • Pentest notes workspace (CherryTree-style, main content)
 * • Sidebar with modal-open tabs (Checklist, Documentation, Credentials, Findings, Evidence)
 * • Recent activity feed
 */
function renderMachineDetail(machine) {
  const progress = getTotalProgress(machine);
  const recentActivity = machineActivity(machine.id).slice(0, 20);

  state.ui.machineTab = 'notes';

  return `
    <section>
      <button class="btn btn-ghost" id="backToDashboard">← Back to Dashboard</button>
      <div class="machine-top">
        <div>
          <div class="machine-title-row">
            <h1 class="mono machine-ip-copy" style="font-size:3.1rem;cursor:pointer" title="Click to copy IP" data-copy-ip="${machine.ip}">🖥 ${machine.ip}</h1>
            <button class="icon-btn edit-inline-btn" data-edit-field="ip" title="Edit IP">✎</button>
          </div>
          <p class="small machine-created mono">Created: ${formatDate(machine.created_at)}</p>
        </div>
        <div class="machine-controls">
          <div class="status-row">
            <span class="status-label">STATUS:</span>
            <select id="machineStatus">
              <option value="pending" ${machine.status === 'pending' ? 'selected' : ''}>None</option>
              <option value="scanning" ${machine.status === 'scanning' ? 'selected' : ''}>Initial Recon</option>
              <option value="user_shell" ${machine.status === 'user_shell' ? 'selected' : ''}>Low-Level Exploited</option>
              <option value="root_shell" ${machine.status === 'root_shell' ? 'selected' : ''}>Root-Level Exploited</option>
              <option value="completed" ${machine.status === 'completed' ? 'selected' : ''}>Completed</option>
            </select>
          </div>
          <div class="progress-row">
            <span class="small checklist-progress-label">Checklist Progress</span>
            <div class="progress-inline">
              <div class="progress-bar" style="width:110px"><div class="progress-fill" style="width:${progress}%"></div></div>
              <span class="mono" style="color:var(--green)">${progress}%</span>
            </div>
          </div>
          <div class="machine-right-meta">
            <p class="small mono machine-meta-line">Operating System: ${machine.os_type === 'windows' ? 'Windows' : 'Linux'} <button class="icon-btn edit-inline-btn" data-edit-field="os_type" title="Edit OS">✎</button></p>
            <p class="small mono machine-meta-line">Domain Name: ${machine.hostname || '-'} <button class="icon-btn edit-inline-btn" data-edit-field="hostname" title="Edit Domain">✎</button></p>
          </div>
        </div>
      </div>

      <div class="mm-section-title" id="mm-viewport-${machine.id}">
        <span class="mm-section-icon">⬡</span>
        <span class="mm-section-label">MIND MAP</span>
        <span class="mm-section-line"></span>
      </div>
      ${renderMachineMindMap(machine)}

      <div class="machine-content-layout">
        <div class="machine-main">${renderNotesWorkspace(machine)}</div>
        <aside class="machine-side sticky-side">
          <div class="tabs tabs-vertical sticky-tabs">
            <button class="tab" id="scrollToMindMap">🌐 Mind Map</button>
            <button class="tab" id="openCredModalTab">🔑 Credentials (${machineCredentials(machine.id).length})</button>
            <button class="tab" id="openDocumentationTab">📄 Documentation</button>
            <button class="tab" id="openChecklistTab">📋 Checklist</button>
            <button class="tab" id="openAiDocumentationTab">🤖 AI Penetration Testing</button>
          </div>
          <div class="notes-tree">
            <div class="notes-tree-header">
              <span class="subhead">Phases</span>
            </div>
            <div class="notes-tree-list">
              ${buildPhaseListHtml(machine)}
            </div>
          </div>
        </aside>
      </div>

      ${recentActivity.length ? `
        <div class="recent-box">
          <h3 class="subhead">Recent Activity</h3>
          <div class="recent-scroll">
            ${recentActivity.map((entry) => `<div class="recent-row"><span class="small mono dim">${formatTime(entry.timestamp)}</span><span class="badge mono">${formatActionLabel(entry.action)}</span><span class="small">${entry.details}</span></div>`).join('')}
          </div>
        </div>
      ` : ''}
    </section>
  `;
}

/* ───────────────────────────────────────────────
  22. Router / Mount
   ─────────────────────────────────────────────── */

/**
 * Main entry point: reads the hash route and renders the appropriate page.
 * Tears down any open modals/fullscreen state before rendering.
 */
function mount() {
  /* Save any in-progress note content before DOM is destroyed */
  {
    const prevPath = routePath();
    const prevMid = parseMachineRoute(prevPath);
    if (prevMid) {
      const prevMachine = machineById(prevMid);
      if (prevMachine) saveActiveNoteContent(prevMachine);
    }
  }
  setNav();
  document.body.classList.remove('mm-fs-active');
  mmFsMachineId = null;
  document.querySelectorAll('dialog[open]').forEach((dialogEl) => {
    try { dialogEl.close(); } catch {}
    dialogEl.removeAttribute('open');
  });
  releaseModalLocks();
  const path = routePath();
  const machineId = parseMachineRoute(path);

  if (machineId) {
    const machine = machineById(machineId);
    if (!machine) {
      main.innerHTML = '<div class="empty"><h3>Machine not found</h3><a href="#/" class="btn btn-ghost">Go Back</a></div>';
      return;
    }
    main.innerHTML = renderMachineDetail(machine);
    wireMachineDetail(machine);
    persistSoon();
    return;
  }

  if (path.startsWith('/timeline')) {
    main.innerHTML = renderTimeline();
    persistSoon();
    return;
  }

  main.innerHTML = renderDashboard();
  wireDashboard();
  updateStorageMeters();
  persistSoon();
}

/* ───────────────────────────────────────────────
  23. Modal Display (showDialogSafely)
   ─────────────────────────────────────────────── */

/**
 * Safely open a <dialog> as a modal, locking background scroll.
 * Installs close handlers that restore scroll position and release
 * the body overflow lock.  Watches for [open] attribute removal.
 */
function showDialogSafely(modal) {
  if (!modal) return;

  const lockBackgroundScroll = () => {
    if (isMainScrollLocked) return;
    isMainScrollLocked = true;

    document.body.classList.add('modal-active');
    document.documentElement.classList.add('modal-active');
    document.documentElement.style.overflow = 'hidden';
    document.body.style.overflow = 'hidden';

    if (main) {
      mainScrollLockTop = main.scrollTop;
      main.style.overflow = 'hidden';
      mainScrollLockHandler = () => {
        if (!isMainScrollLocked || !main) return;
        if (main.scrollTop !== mainScrollLockTop) {
          main.scrollTop = mainScrollLockTop;
        }
      };
      main.addEventListener('scroll', mainScrollLockHandler, { passive: true });
    }
  };

  const unlockBackgroundScroll = () => {
    if (!isMainScrollLocked) return;
    releaseModalLocks();
    if (main) main.scrollTop = mainScrollLockTop;
  };

  const syncModalBodyState = () => {
    const anyOpen = document.querySelectorAll('dialog[open]').length > 0;
    if (anyOpen) lockBackgroundScroll();
    else unlockBackgroundScroll();
  };

  if (modal.open) {
    try { modal.close(); } catch {}
  }

  lockBackgroundScroll();

  try {
    modal.showModal();
  } catch {
    unlockBackgroundScroll();
    return;
  }
  syncModalBodyState();

  const onClose = () => {
    syncModalBodyState();
    modal.removeEventListener('close', onClose);
  };

  modal.addEventListener('close', onClose);
}

/* ───────────────────────────────────────────────
  24. Event Wiring
   Each wire* function attaches event listeners to the DOM created
   by its matching render* function.  These must be called after every
   innerHTML injection because the old DOM nodes (and their handlers)
   are destroyed on re-render.
   ─────────────────────────────────────────────── */

/* ── XML Import / Export ─────────────────────── */

/** Escape special XML characters in a string value. */
function xmlEsc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Convert a JS value to an XML string representation. */
function valueToXml(val, indent) {
  if (val === null || val === undefined) return `${indent}<null/>`;
  if (typeof val === 'boolean') return `${indent}<boolean>${val}</boolean>`;
  if (typeof val === 'number') return `${indent}<number>${val}</number>`;
  if (typeof val === 'string') return `${indent}<string>${xmlEsc(val)}</string>`;
  if (Array.isArray(val)) {
    if (val.length === 0) return `${indent}<array/>`;
    const items = val.map(item => `${indent}  <item>\n${valueToXml(item, indent + '    ')}\n${indent}  </item>`).join('\n');
    return `${indent}<array>\n${items}\n${indent}</array>`;
  }
  if (typeof val === 'object') {
    const keys = Object.keys(val);
    if (keys.length === 0) return `${indent}<object/>`;
    const entries = keys.map(k => `${indent}  <entry key="${xmlEsc(k)}">\n${valueToXml(val[k], indent + '    ')}\n${indent}  </entry>`).join('\n');
    return `${indent}<object>\n${entries}\n${indent}</object>`;
  }
  return `${indent}<string>${xmlEsc(String(val))}</string>`;
}

/** Parse an XML element back into a JS value. */
function xmlToValue(el) {
  const tag = el.tagName.toLowerCase();
  if (tag === 'null') return null;
  if (tag === 'boolean') return el.textContent.trim() === 'true';
  if (tag === 'number') return Number(el.textContent.trim());
  if (tag === 'string') return el.textContent;
  if (tag === 'array') {
    const items = Array.from(el.children).filter(c => c.tagName.toLowerCase() === 'item');
    return items.map(item => {
      const child = item.children[0];
      return child ? xmlToValue(child) : null;
    });
  }
  if (tag === 'object') {
    const obj = {};
    Array.from(el.children).filter(c => c.tagName.toLowerCase() === 'entry').forEach(entry => {
      const key = entry.getAttribute('key');
      const child = entry.children[0];
      obj[key] = child ? xmlToValue(child) : null;
    });
    return obj;
  }
  return el.textContent;
}

/**
 * Export all application state + evidence blobs to an XML file and download it.
 * Evidence files are base64-encoded inline so the export is fully portable.
 */
async function exportToXml() {
  const statusEl = document.getElementById('exportXmlBtn');
  const origLabel = statusEl ? statusEl.textContent : '';
  try {
    if (statusEl) { statusEl.textContent = '⏳ Exporting...'; statusEl.disabled = true; }

    /* Collect all evidence IDs referenced in machine item_evidence */
    const evidenceIds = new Set();
    for (const machine of state.machines) {
      if (machine.item_evidence) {
        for (const entries of Object.values(machine.item_evidence)) {
          for (const entry of (entries || [])) {
            if (entry.id) evidenceIds.add(entry.id);
          }
        }
      }
      for (const entry of (machine.archived_evidence || [])) {
        if (entry.id) evidenceIds.add(entry.id);
      }
    }
    /* Also collect evidence from findings */
    for (const finding of state.findings) {
      for (const entry of (finding.evidence || [])) {
        if (entry.id) evidenceIds.add(entry.id);
      }
    }

    /* Read evidence blobs from IndexedDB and base64-encode them */
    let evidenceXml = '';
    for (const id of evidenceIds) {
      try {
        const record = await getEvidenceFile(id);
        if (record && record.blob) {
          const buffer = await record.blob.arrayBuffer();
          const bytes = new Uint8Array(buffer);
          let binary = '';
          for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
          const b64 = btoa(binary);
          evidenceXml += `    <evidence id="${xmlEsc(record.id)}" name="${xmlEsc(record.name)}" type="${xmlEsc(record.type)}" size="${record.size}">\n      ${b64}\n    </evidence>\n`;
        }
      } catch { /* skip unreadable evidence */ }
    }

    /* Build the complete XML */
    const statePayload = {
      machines: state.machines,
      credentials: state.credentials,
      findings: state.findings,
      activities: state.activities,
    };

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<SecurityTrackerExport version="1" exported="' + xmlEsc(nowStamp()) + '">\n';
    xml += '  <state>\n' + valueToXml(statePayload, '    ') + '\n  </state>\n';
    if (evidenceXml) {
      xml += '  <evidenceStore>\n' + evidenceXml + '  </evidenceStore>\n';
    }
    xml += '</SecurityTrackerExport>\n';

    /* Download */
    const blob = new Blob([xml], { type: 'application/xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const dateStr = new Date().toISOString().slice(0, 10);
    a.download = `security-tracker-export-${dateStr}.xml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    if (statusEl) { statusEl.textContent = '✓ Exported!'; setTimeout(() => { statusEl.textContent = origLabel; statusEl.disabled = false; }, 2000); }
  } catch (err) {
    console.error('Export failed:', err);
    if (statusEl) { statusEl.textContent = origLabel; statusEl.disabled = false; }
    alert('Export failed: ' + err.message);
  }
}

/**
 * Import state + evidence from an XML file.
 * Prompts user to merge with or replace existing data.
 */
async function importFromXml(file) {
  try {
    const text = await file.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(text, 'application/xml');

    /* Check for parse errors */
    const parseError = doc.querySelector('parsererror');
    if (parseError) throw new Error('Invalid XML file');

    const root = doc.documentElement;
    if (root.tagName !== 'SecurityTrackerExport') throw new Error('Not a Security Tracker export file');

    /* Parse state */
    const stateEl = root.querySelector(':scope > state');
    if (!stateEl) throw new Error('No state data found in XML');
    const stateChild = stateEl.children[0];
    if (!stateChild) throw new Error('Empty state data');
    const imported = xmlToValue(stateChild);

    const importedMachines = imported.machines || [];
    const importedCredentials = imported.credentials || [];
    const importedFindings = imported.findings || [];
    const importedActivities = imported.activities || [];

    if (importedMachines.length === 0) {
      alert('No machines found in the XML file.');
      return;
    }

    /* Ask user: merge or replace */
    let mode = 'replace';
    if (state.machines.length > 0) {
      const choice = confirm(
        `Found ${importedMachines.length} machine(s) in the XML file.\n\n` +
        `You currently have ${state.machines.length} machine(s).\n\n` +
        `OK = Replace all current data\nCancel = Cancel import`
      );
      if (!choice) return;
    }

    /* Replace state data */
    state.machines = importedMachines.map(m => ({
      ...m,
      selected_ports: m.selected_ports || [],
      completed_items: m.completed_items || [],
      item_notes: m.item_notes || {},
      item_evidence: m.item_evidence || {},
      archived_evidence: m.archived_evidence || [],
      archived_credentials: m.archived_credentials || [],
    }));
    state.credentials = importedCredentials.map(c => ({
      ...c,
      finding_id: c.finding_id || null,
      created_at: c.created_at || nowStamp(),
    }));
    state.findings = importedFindings.map(f => ({
      ...f,
      evidence: f.evidence || [],
      phase: f.phase || 'osint',
      severity: f.severity || 'info',
      category: f.category || 'finding',
      parent_id: f.parent_id || null,
      source_checklist_item_id: f.source_checklist_item_id || null,
      created_at: f.created_at || nowStamp(),
      updated_at: f.updated_at || f.created_at || nowStamp(),
    }));
    state.activities = importedActivities;
    state.reveal = {};

    /* Restore evidence blobs to IndexedDB */
    const evidenceStoreEl = root.querySelector(':scope > evidenceStore');
    if (evidenceStoreEl) {
      await clearEvidenceStore();
      const evidenceEls = evidenceStoreEl.querySelectorAll(':scope > evidence');
      for (const evEl of evidenceEls) {
        try {
          const id = evEl.getAttribute('id');
          const name = evEl.getAttribute('name') || 'unknown';
          const type = evEl.getAttribute('type') || 'application/octet-stream';
          const b64 = evEl.textContent.trim();
          if (!b64) continue;

          const binary = atob(b64);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          const blob = new Blob([bytes], { type });

          const database = await openEvidenceDb();
          await new Promise((resolve, reject) => {
            const tx = database.transaction(EVIDENCE_STORE_NAME, 'readwrite');
            tx.objectStore(EVIDENCE_STORE_NAME).put({
              id,
              blob,
              name,
              type,
              size: bytes.length,
              created_at: nowStamp(),
            });
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
          });
        } catch (evErr) {
          console.warn('Failed to restore evidence:', evErr);
        }
      }
    }

    persist();
    addActivity('imported_data', `Imported ${importedMachines.length} machine(s) from XML`, '');
    mount();
    alert(`Successfully imported ${importedMachines.length} machine(s).`);
  } catch (err) {
    console.error('Import failed:', err);
    alert('Import failed: ' + err.message);
  }
}

/** Wire dashboard page: Add Machine button, delete machine, machine card clicks, Reset, Import/Export. */
function wireDashboard() {
  document.getElementById('openMachineModal')?.addEventListener('click', () => {
    fillMachineSelect();
    showDialogSafely(document.getElementById('machineModal'));
  });

  /* ── XML Export ── */
  document.getElementById('exportXmlBtn')?.addEventListener('click', () => exportToXml());

  /* ── XML Import ── */
  const importBtn = document.getElementById('importXmlBtn');
  const importInput = document.getElementById('xmlImportInput');
  importBtn?.addEventListener('click', () => importInput?.click());
  importInput?.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (file) importFromXml(file);
    e.target.value = '';   // reset so same file can be re-imported
  });

  document.getElementById('resetMachinesBtn')?.addEventListener('click', async () => {
    if (!state.machines.length) return;
    const confirmed = window.confirm('Reset all machines and related data? This cannot be undone.');
    if (!confirmed) return;

    await clearEvidenceStore();

    state.machines = [];
    state.credentials = [];
    state.findings = [];
    state.activities = [];
    state.reveal = {};
    state.ui.machineTab = 'checklist';
    state.ui.showAddMachineCred = false;
    state.ui.showAddFinding = false;
    mount();
  });

  main.querySelectorAll('.machine-card').forEach((card) => {
    card.addEventListener('click', (event) => {
      if (event.target.closest('[data-delete-machine]')) return;
      window.location.hash = `#/machine/${card.dataset.machineId}`;
    });
  });

  main.querySelectorAll('[data-delete-machine]').forEach((button) => {
    button.addEventListener('click', (event) => {
      event.stopPropagation();
      if (!armConfirmButton(button)) return;
      const id = button.dataset.deleteMachine;
      const machine = machineById(id);
      if (!machine) return;
      const removedCreds = state.credentials.filter((credential) => credential.machine_id === id).length;
      const removedFindings = state.findings.filter((finding) => finding.machine_id === id).length;
      state.credentials = state.credentials.filter((credential) => credential.machine_id !== id);
      state.findings = state.findings.filter((finding) => finding.machine_id !== id);
      state.activities = state.activities.filter((activity) => activity.machine_id !== id);
      state.machines = state.machines.filter((entry) => entry.id !== id);
      addActivity('updated_machine', `Deleted machine ${machine.ip}; removed ${removedCreds} credential(s) and ${removedFindings} finding(s)`, id);
      mount();
    });
  });
}

/**
 * Wire the inline-fullscreen toggle button on the mind map.
 * Handles expanding to fill the viewport and collapsing back,
 * preserving scroll position across transitions.
 */
function wireMMFullscreenBtn(machine, mmEl) {
  const fsBtn = mmEl.querySelector('#mm-fs-' + machine.id);
  if (!fsBtn) return;
  if (mmEl._fsCleanup) { mmEl._fsCleanup(); delete mmEl._fsCleanup; }

  const syncBtn = () => {
    const isFs = mmEl.classList.contains('mm-inline-fullscreen');
    fsBtn.innerHTML = isFs ? 'Exit Full-Screen &#x2B1B;' : 'Full-Screen &#x26F6;';
    fsBtn.title = isFs ? 'Exit Full-Screen' : 'Full-Screen';
  };

  const closeInlineFullscreen = () => {
    if (mmFsMachineId !== machine.id) return;
    const restoreY = mmEl._savedScrollY || 0;
    mmEl.classList.remove('mm-inline-fullscreen');
    document.body.classList.remove('mm-fs-active');
    mmFsMachineId = null;
    state.ui.mmPhase = 'all';
    syncBtn();
    refreshMindMapInPlace(machine);
    /* Restore scroll position after layout settles */
    requestAnimationFrame(() => {
      const mainEl = document.getElementById('main');
      if (mainEl) { mainEl.scrollTop = restoreY; }
      requestAnimationFrame(() => {
        if (mainEl) { mainEl.scrollTop = restoreY; }
      });
    });
  };

  const openInlineFullscreen = () => {
    const mainEl = document.getElementById('main');
    mmEl._savedScrollY = mainEl ? mainEl.scrollTop : 0;
    document.querySelectorAll('.machine-mindmap.mm-inline-fullscreen').forEach(el => {
      el.classList.remove('mm-inline-fullscreen');
    });
    mmEl.classList.add('mm-inline-fullscreen');
    document.body.classList.add('mm-fs-active');
    mmFsMachineId = machine.id;
    state.ui.mmPhase = 'all';
    syncBtn();
    refreshMindMapInPlace(machine);
  };

  const onToggleClick = () => {
    if (mmEl.classList.contains('mm-inline-fullscreen')) closeInlineFullscreen();
    else openInlineFullscreen();
  };

  const onEsc = (event) => {
    if (event.key === 'Escape' && mmEl.classList.contains('mm-inline-fullscreen')) {
      closeInlineFullscreen();
    }
  };

  fsBtn.addEventListener('click', onToggleClick);
  window.addEventListener('keydown', onEsc);
  syncBtn();

  mmEl._fsCleanup = () => {
    fsBtn.removeEventListener('click', onToggleClick);
    window.removeEventListener('keydown', onEsc);
  };
}

/**
 * Re-render just the mind map area without a full page mount().
 * Preserves the surrounding page state (checklist, sidebar, etc.).
 */
function refreshMindMapInPlace(machine) {
  const mmEl = document.getElementById('mm-container-' + machine.id);
  if (!mmEl) { mount(); return; }
  const tmp = document.createElement('div');
  tmp.innerHTML = renderMachineMindMap(machine).trim();
  const newInner = tmp.firstElementChild;
  mmEl.innerHTML = newInner ? newInner.innerHTML : '';
  /* Re-wire phase buttons */
  mmEl.querySelectorAll('[data-mm-phase]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.ui.mmPhase = btn.dataset.mmPhase;
      if (mmFsMachineId === machine.id) { refreshMindMapInPlace(machine); }
      else { mount(); }
    });
  });
  wireMindMapPanZoom(machine);
  wireMMFullscreenBtn(machine, mmEl);
  /* Wire heading jump clicks */
  wireMMHeadingJumps(machine, mmEl);
  /* Wire draggable blocks in fullscreen */
  wireFsBlockDrag(mmEl, machine);
}

/**
 * Wire heading node clicks in the mind map.
 * Clicking a heading navigates to the phase notes and scrolls to that heading.
 */
function wireMMHeadingJumps(machine, root) {
  root.querySelectorAll('[data-mm-heading-jump]').forEach(btn => {
    btn.addEventListener('click', () => {
      const phaseId = btn.dataset.mmHeadingJump;
      const headingIndex = parseInt(btn.dataset.mmHeadingIndex, 10);
      /* Exit fullscreen if active */
      if (mmFsMachineId === machine.id) {
        const mmEl = document.getElementById('mm-container-' + machine.id);
        if (mmEl) {
          mmEl.classList.remove('mm-inline-fullscreen');
          document.body.classList.remove('mm-fs-active');
          mmFsMachineId = null;
        }
      }
      /* Navigate to the phase */
      state.ui.activeNoteId = phaseId;
      persist();
      mount();
      /* After mount, scroll to the heading in the editor */
      requestAnimationFrame(() => {
        const editorBody = document.getElementById('notesEditorBody');
        if (!editorBody) return;
        const headings = editorBody.querySelectorAll('h1, h2, h3');
        const target = headings[headingIndex];
        if (target) {
          target.scrollIntoView({ behavior: 'smooth', block: 'center' });
          /* Brief highlight flash */
          target.style.transition = 'background .2s';
          target.style.background = 'rgba(124,58,237,.25)';
          setTimeout(() => { target.style.background = ''; }, 1200);
        }
      });
    });
  });
}

/* ───────────────────────────────────────────────
  25. Mind Map Interactivity
   SVG connectors, pan/zoom, fullscreen drag, lane scroll arrows.
   ─────────────────────────────────────────────── */

/** Attach click handlers to the up/down lane scroll arrows within the mind map. */
function wireLaneScrollArrows(root) {
  root.querySelectorAll('.mm-lane-scroll-wrap').forEach(wrap => {
    const body    = wrap.querySelector('.mm-phase-lane-body') || wrap.querySelector('.mm-day-col-body');
    const arrowUp = wrap.querySelector('.mm-lane-arrow--up');
    const arrowDn = wrap.querySelector('.mm-lane-arrow--down');
    if (!body || !arrowUp || !arrowDn) return;

    const SCROLL_STEP = 80; // px per click

    const sync = () => {
      const hasOverflow = body.scrollHeight > body.clientHeight + 2;
      const atTop    = body.scrollTop <= 1;
      const atBottom = body.scrollTop + body.clientHeight >= body.scrollHeight - 1;
      // Dim arrows that can't scroll further; fully hide both if no overflow at all
      arrowUp.classList.toggle('mm-lane-arrow--disabled', !hasOverflow || atTop);
      arrowDn.classList.toggle('mm-lane-arrow--disabled', !hasOverflow || atBottom);
      wrap.classList.toggle('mm-lane-scroll-wrap--no-overflow', !hasOverflow);
    };

    arrowUp.addEventListener('click', (e) => { e.stopPropagation(); body.scrollBy({ top: -SCROLL_STEP, behavior: 'smooth' }); });
    arrowDn.addEventListener('click', (e) => { e.stopPropagation(); body.scrollBy({ top:  SCROLL_STEP, behavior: 'smooth' }); });
    let laneScrollRaf = 0;
    body.addEventListener('scroll', () => {
      if (!laneScrollRaf) laneScrollRaf = requestAnimationFrame(() => { laneScrollRaf = 0; sync(); });
    }, { passive: true });

    // Initial sync after a tick (layout needs to settle)
    requestAnimationFrame(sync);
  });
}

/* ── Draw SVG arrows for cross-phase parent links (fullscreen only) ──
 *  SYNCHRONOUS — must be called after layout is ready (inside rAF or
 *  after repositionFsBlocks).  Uses getBoundingClientRect subtraction
 *  so it is immune to CSS transforms on the pan-canvas.
 */
/**
 * Draw dashed SVG arrows between phase lanes for findings that
 * have cross-phase parent relationships (e.g. recon → exploitation).
 */
function drawCrossPhaseArrows(mmEl, machine) {
  // Remove existing overlay
  mmEl.querySelectorAll('.mm-xphase-svg').forEach(el => el.remove());

  /* works in both default and fullscreen modes — just needs mm-fs-workspace */

  const allFindings = machineFindings(machine.id);
  const canvasEl = document.getElementById('mm-canvas-' + machine.id);
  if (!canvasEl) return;

  const workspace = canvasEl.querySelector('.mm-fs-workspace');
  if (!workspace) return;

  // Find cross-phase links: child is in a different phase than its parent
  const crossLinks = [];
  allFindings.forEach(child => {
    if (!child.parent_id) return;
    const parent = allFindings.find(p => p.id === child.parent_id);
    if (!parent || parent.phase === child.phase) return;
    crossLinks.push({ parentId: parent.id, childId: child.id });
  });

  if (!crossLinks.length) return;

  // Create SVG overlay
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.classList.add('mm-xphase-svg');
  svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  workspace.appendChild(svg);

  /*
   * Use getBoundingClientRect subtraction: both workspace and nodes live
   * inside the same transformed pan-canvas, so subtracting the workspace
   * rect from the node rect cancels the transform.  Divide by scale to
   * convert screen-space deltas back to CSS-pixel coords for the SVG.
   */
  const wsRect = workspace.getBoundingClientRect();
  const scale  = wsRect.width / (workspace.offsetWidth || 1) || 1;

  let maxX = 0, maxY = 0;

  crossLinks.forEach(link => {
    const parentNode = workspace.querySelector(`[data-mm-fid="${link.parentId}"] > .mm-node`);
    const childNode  = workspace.querySelector(`[data-mm-fid="${link.childId}"] > .mm-node`);
    if (!parentNode || !childNode) return;

    const pr = parentNode.getBoundingClientRect();
    const cr = childNode.getBoundingClientRect();

    /* Positions relative to workspace, in CSS pixels */
    const x1 = (pr.right - wsRect.left) / scale;
    const y1 = ((pr.top + pr.height / 2) - wsRect.top) / scale;
    const x2 = (cr.left - wsRect.left) / scale;
    const y2 = ((cr.top + cr.height / 2) - wsRect.top) / scale;

    /* Smooth cubic bezier curve with looping arc */
    const dy = y2 - y1;
    const dx = Math.abs(x2 - x1) || 60;
    const arcDist = Math.max(Math.min(Math.abs(dy) * 0.4, 80), 30);
    const arcDir  = dy >= 0 ? 1 : -1;

    const cx1 = x1 + dx * 0.25;
    const cy1 = y1 + arcDist * arcDir;
    const cx2 = x2 - dx * 0.25;
    const cy2 = y2 + arcDist * arcDir;

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', `M ${x1} ${y1} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${x2} ${y2}`);
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', '#22c55e');
    path.setAttribute('stroke-width', '2');
    path.setAttribute('stroke-dasharray', '8 4');
    path.classList.add('mm-xphase-line');
    svg.appendChild(path);

    maxX = Math.max(maxX, x1, x2 + 10, cx1, cx2);
    maxY = Math.max(maxY, y1 + 10, y2 + 10, Math.abs(cy1) + 10, Math.abs(cy2) + 10);
  });

  svg.setAttribute('width', maxX + 40);
  svg.setAttribute('height', maxY + 40);
  svg.style.width  = (maxX + 40) + 'px';
  svg.style.height = (maxY + 40) + 'px';
}

/* ── Draw SVG connector curves for parent→child and finding→credential links ── */
/**
 * Draw SVG connector lines from parent findings to child findings
 * and from findings to their linked credential blobs.
 */
function drawLeafConnectors(root) {
  root.querySelectorAll('.mm-leaf-conn-svg').forEach(el => el.remove());

  requestAnimationFrame(() => {
    root.querySelectorAll('.mm-leaf-row').forEach(row => {
      const parentNode = row.querySelector(':scope > .mm-node');
      if (!parentNode) return;

      const leaves    = row.querySelector(':scope > .mm-leaves');
      const credChain = row.querySelector(':scope > .mm-cred-chain');
      if (!leaves && !credChain) return;

      row.style.position = 'relative';
      const rowRect = row.getBoundingClientRect();
      const scale   = rowRect.width / (row.offsetWidth || 1) || 1;

      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.classList.add('mm-leaf-conn-svg');

      let paths = '';
      const pr = parentNode.getBoundingClientRect();
      const x1 = (pr.right - rowRect.left) / scale;
      const y1 = ((pr.top + pr.height / 2) - rowRect.top) / scale;

      /* parent → children curves */
      if (leaves) {
        leaves.querySelectorAll(':scope > .mm-leaf-row').forEach(childRow => {
          const childNode = childRow.querySelector(':scope > .mm-node');
          if (!childNode) return;
          const cr = childNode.getBoundingClientRect();
          const x2 = (cr.left - rowRect.left) / scale;
          const y2 = ((cr.top + cr.height / 2) - rowRect.top) / scale;
          const mx = (x1 + x2) / 2;
          paths += `<path d="M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}" class="mm-leaf-conn-child"/>`;
        });
      }

      /* finding → credential curves */
      if (credChain) {
        credChain.querySelectorAll(':scope > .mm-cred-blob').forEach(blob => {
          const cr = blob.getBoundingClientRect();
          const x2 = (cr.left - rowRect.left) / scale;
          const y2 = ((cr.top + cr.height / 2) - rowRect.top) / scale;
          const mx = (x1 + x2) / 2;
          paths += `<path d="M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}" class="mm-leaf-conn-cred"/>`;
        });
      }

      svg.innerHTML = paths;
      const w = row.scrollWidth;
      const h = row.scrollHeight;
      svg.setAttribute('width', w);
      svg.setAttribute('height', h);
      svg.style.width  = w + 'px';
      svg.style.height = h + 'px';
      row.appendChild(svg);
    });
  });
}

/* ── Reposition fullscreen blocks based on actual rendered sizes ── */
/** Auto-position the fullscreen drag blocks in a grid layout. */
function repositionFsBlocks(workspace) {
  if (!workspace) return;
  /* Build phase sequence from the DOM blocks actually present.
     Start with the canonical order, keep only IDs that have a block,
     then append any extras. */
  const canonicalIds = checklistPhases.map(p => p.id);
  const presentIds = new Set();
  workspace.querySelectorAll('[data-mm-drag-block]').forEach(b => presentIds.add(b.dataset.mmDragBlock));
  const PHASE_SEQ = canonicalIds.filter(pid => presentIds.has(pid));
  presentIds.forEach(pid => {
    if (!PHASE_SEQ.includes(pid)) PHASE_SEQ.push(pid);
  });
  const GAP = 60;
  let x = 20;
  PHASE_SEQ.forEach((pid, i) => {
    const block = workspace.querySelector(`[data-mm-drag-block="${pid}"]`);
    if (!block) return;
    block.style.left = x + 'px';
    block.style.top  = (40 + (i % 2) * 30) + 'px';
    x += (block.offsetWidth || 280) + GAP;
  });
  /* Grow workspace to fit */
  workspace.style.minWidth = (x + 40) + 'px';
}

/* ── Draggable free-form blocks for fullscreen ── */
/**
 * Make fullscreen mind-map blocks draggable via their header bars.
 * After drag ends, saves positions and redraws connectors.
 */
function wireFsBlockDrag(mmEl, machine) {
  const workspace = mmEl.querySelector('.mm-fs-workspace');
  if (!workspace) return;

  /* Get current canvas scale to compensate drag deltas */
  const canvasEl = workspace.closest('.mm-pan-canvas');
  function getCanvasScale() {
    if (!canvasEl) return 1;
    const m = canvasEl.style.transform.match(/scale\(([\d.]+)\)/);
    return m ? parseFloat(m[1]) || 1 : 1;
  }

  const blocks = workspace.querySelectorAll('[data-mm-drag-block]');
  blocks.forEach(block => {
    const handle = block.querySelector('[data-mm-drag-handle]');
    if (!handle) return;

    let dragging = false, startX = 0, startY = 0, origLeft = 0, origTop = 0;

    handle.style.cursor = 'grab';

    const onDown = (e) => {
      e.preventDefault();
      e.stopPropagation();
      dragging = true;
      startX = e.clientX;
      startY = e.clientY;
      origLeft = parseInt(block.style.left) || 0;
      origTop  = parseInt(block.style.top)  || 0;
      handle.style.cursor = 'grabbing';
      block.style.zIndex = '50';
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
    };

    const onMove = (e) => {
      if (!dragging) return;
      const s  = getCanvasScale();
      const dx = (e.clientX - startX) / s;
      const dy = (e.clientY - startY) / s;
      block.style.left = (origLeft + dx) + 'px';
      block.style.top  = (origTop  + dy) + 'px';
    };

    const onUp = () => {
      dragging = false;
      handle.style.cursor = 'grab';
      block.style.zIndex = '';
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      updateFsConnectors(workspace);
      drawCrossPhaseArrows(mmEl, machine);
      /* Save all block positions */
      saveFsBlockPositions(workspace, machine);
    };

    handle.addEventListener('mousedown', onDown);
  });

  /* Reposition blocks based on actual sizes, then draw connectors */
  requestAnimationFrame(() => {
    repositionFsBlocks(workspace);
    /* Restore saved block positions if available */
    restoreFsBlockPositions(workspace, machine);
    updateFsConnectors(workspace);
    drawCrossPhaseArrows(mmEl, machine);
  });
}

/* ── Save / restore fullscreen block positions ── */
/** Persist block positions (x,y per phase) to state.ui.mmViewState. */
function saveFsBlockPositions(workspace, machine) {
  if (!workspace || !machine) return;
  if (!state.ui.mmViewState) state.ui.mmViewState = {};
  if (!state.ui.mmViewState[machine.id]) state.ui.mmViewState[machine.id] = {};
  const positions = {};
  workspace.querySelectorAll('[data-mm-drag-block]').forEach(b => {
    positions[b.dataset.mmDragBlock] = {
      left: parseInt(b.style.left) || 0,
      top:  parseInt(b.style.top)  || 0,
    };
  });
  state.ui.mmViewState[machine.id].blocks = positions;
  persist();
}

/** Restore saved block positions from state, falling back to auto-layout. */
function restoreFsBlockPositions(workspace, machine) {
  if (!workspace || !machine) return;
  const saved = state.ui.mmViewState?.[machine.id]?.blocks;
  if (!saved) return;
  workspace.querySelectorAll('[data-mm-drag-block]').forEach(b => {
    const pos = saved[b.dataset.mmDragBlock];
    if (pos) {
      b.style.left = pos.left + 'px';
      b.style.top  = pos.top  + 'px';
    }
  });
  /* Grow workspace to fit restored positions */
  let maxRight = 0;
  workspace.querySelectorAll('[data-mm-drag-block]').forEach(b => {
    maxRight = Math.max(maxRight, (parseInt(b.style.left) || 0) + (b.offsetWidth || 280));
  });
  workspace.style.minWidth = (maxRight + 40) + 'px';
}

/* Position the SVG connector lines between adjacent phase blocks */
/** Redraw the SVG connector lines between fullscreen phase blocks. */
function updateFsConnectors(workspace) {
  if (!workspace) return;
  const svg = workspace.querySelector('.mm-fs-connectors-svg');
  if (!svg) return;

  /* Build phase sequence from the DOM blocks actually present.
     Start with the canonical order (so phases stay in the right order),
     keep only IDs that have a block, then append any extras. */
  const canonicalIds = checklistPhases.map(p => p.id);
  const presentIds = new Set();
  workspace.querySelectorAll('[data-mm-drag-block]').forEach(b => presentIds.add(b.dataset.mmDragBlock));
  const PHASE_SEQ = canonicalIds.filter(pid => presentIds.has(pid));
  /* Include any extra phase blocks present in the DOM */
  presentIds.forEach(pid => {
    if (!PHASE_SEQ.includes(pid)) PHASE_SEQ.push(pid);
  });

  /* Gather block positions */
  const blocks = {};
  workspace.querySelectorAll('[data-mm-drag-block]').forEach(b => {
    const pid = b.dataset.mmDragBlock;
    blocks[pid] = {
      left: parseInt(b.style.left) || 0,
      top:  parseInt(b.style.top)  || 0,
      w:    b.offsetWidth  || 280,
      h:    b.offsetHeight || 120,
    };
  });

  let paths = '';
  let maxW = 0, maxH = 0;

  for (let i = 0; i < PHASE_SEQ.length - 1; i++) {
    const from = blocks[PHASE_SEQ[i]];
    const to   = blocks[PHASE_SEQ[i + 1]];
    if (!from || !to) continue;

    const x1 = from.left + from.w;
    const y1 = from.top  + from.h / 2;
    const x2 = to.left;
    const y2 = to.top + to.h / 2;
    const mx = (x1 + x2) / 2;

    paths += `<path d="M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}"
      fill="none" stroke="rgba(148,163,184,.38)" stroke-width="2"
      stroke-dasharray="6 4" class="mm-conn-path"/>`;

    maxW = Math.max(maxW, x1, x2 + 10);
    maxH = Math.max(maxH, y1, y2 + 10);
  }

  svg.innerHTML = paths;

  svg.setAttribute('width',  maxW + 40);
  svg.setAttribute('height', maxH + 40);
  svg.style.width  = (maxW + 40) + 'px';
  svg.style.height = (maxH + 40) + 'px';
}

/**
 * Attach mouse-based pan and scroll-wheel zoom to the mind-map viewport.
 * Persists the current transform (scale, translateX/Y) in state.ui.mmViewState.
 */
function wireMindMapPanZoom(machine) {
  if (mmPanCleanup) { mmPanCleanup(); mmPanCleanup = null; }
  const vpEl     = document.getElementById('mm-vp-'     + machine.id);
  const canvasEl = document.getElementById('mm-canvas-' + machine.id);
  const mmEl     = document.getElementById('mm-container-' + machine.id);
  if (!vpEl || !canvasEl || !mmEl) return;

  const zoomResetBtn = document.getElementById('mm-zoom-reset-' + machine.id);

  const syncZoomControls = () => {
    if (zoomResetBtn) zoomResetBtn.disabled = false;
  };

  /* ── Restore saved pan/zoom or default ── */
  if (!state.ui.mmViewState) state.ui.mmViewState = {};
  const saved = state.ui.mmViewState[machine.id];
  let tx = saved ? saved.tx : 0;
  let ty = saved ? saved.ty : 0;
  let scale = saved ? saved.scale : 1;
  let dragging = false, startX = 0, startY = 0, startTx = 0, startTy = 0;

  let mmPanRaf = 0;
  canvasEl.style.transformOrigin = '0 0';

  function saveMmView() {
    if (!state.ui.mmViewState) state.ui.mmViewState = {};
    state.ui.mmViewState[machine.id] = { tx, ty, scale };
    persistSoon();
  }

  function applyTransform() {
    canvasEl.style.transform = `translate(${tx}px,${ty}px) scale(${scale})`;
  }
  /* Apply saved transform immediately */
  applyTransform();

  function onMouseDown(e) {
    if (e.button !== 0) return;
    if (e.target.closest('[data-finding-view],[data-mm-phase],.mm-zoom-btn,.mm-fs-btn,[data-mm-drag-handle]')) return;
    dragging = true;
    startX = e.clientX; startY = e.clientY;
    startTx = tx; startTy = ty;
    vpEl.style.cursor = 'grabbing';
    e.preventDefault();
  }

  function onMouseMove(e) {
    if (!dragging) return;
    tx = startTx + (e.clientX - startX);
    ty = startTy + (e.clientY - startY);
    if (!mmPanRaf) mmPanRaf = requestAnimationFrame(() => { mmPanRaf = 0; applyTransform(); });
  }

  function onMouseUp() {
    if (dragging) {
      dragging = false;
      vpEl.style.cursor = '';
      saveMmView();
    }
  }

  function onWheel(e) {
    e.preventDefault();
    const factor  = e.deltaY < 0 ? 1.1 : 1 / 1.1;
    const rect    = vpEl.getBoundingClientRect();
    const mx      = e.clientX - rect.left - tx;
    const my      = e.clientY - rect.top  - ty;
    const newScale = Math.max(0.15, Math.min(4, scale * factor));
    const ratio    = newScale / scale;
    tx -= mx * (ratio - 1);
    ty -= my * (ratio - 1);
    scale = newScale;
    applyTransform();
    saveMmView();
  }

  zoomResetBtn?.addEventListener('click', () => {
    tx = 0;
    ty = 0;
    scale = 1;
    applyTransform();
    /* Clear saved view state for this machine */
    if (state.ui.mmViewState) delete state.ui.mmViewState[machine.id];
    persist();
    vpEl.scrollTo({ top: 0, left: 0, behavior: 'smooth' });
    /* Re-position blocks to their default layout */
    const workspace = mmEl.querySelector('.mm-fs-workspace');
    if (workspace) {
      repositionFsBlocks(workspace);
      updateFsConnectors(workspace);
      drawCrossPhaseArrows(mmEl, machine);
    }
  });

  vpEl.style.userSelect = 'none';
  vpEl.addEventListener('mousedown', onMouseDown);
  window.addEventListener('mousemove', onMouseMove);
  window.addEventListener('mouseup', onMouseUp);
  vpEl.addEventListener('wheel', onWheel, { passive: false });
  syncZoomControls();

  mmPanCleanup = () => {
    vpEl.removeEventListener('mousedown', onMouseDown);
    window.removeEventListener('mousemove', onMouseMove);
    window.removeEventListener('mouseup', onMouseUp);
    vpEl.removeEventListener('wheel', onWheel);
  };
}

/**
 * Master event wiring for the Machine Detail page.
 * Delegates to wireChecklist, wireMachineCredentials, wireFindings,
 * and sets up mind map, sidebar modal tabs, status dropdown,
 * IP copy, inline field editing, and credential panel interactions.
 */
function wireMachineDetail(machine) {
  /* Disconnect any stale observers / pan listeners */
  if (mmResizeObserver) { mmResizeObserver.disconnect(); mmResizeObserver = null; }

  /* --- Mind map phase filter buttons --- */
  document.querySelectorAll('[data-mm-phase]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.ui.mmPhase = btn.dataset.mmPhase;
      if (mmFsMachineId === machine.id) { refreshMindMapInPlace(machine); }
      else { mount(); }
    });
  });

  /* --- Mind map pan/zoom --- */
  wireMindMapPanZoom(machine);

  /* --- Mind map fullscreen --- */
  const _mmContainerEl = document.getElementById('mm-container-' + machine.id);
  if (_mmContainerEl) wireMMFullscreenBtn(machine, _mmContainerEl);

  /* --- Mind map scroll button --- */
  document.getElementById('scrollToMindMap')?.addEventListener('click', () => {
    const mmContainerEl = document.getElementById('mm-container-' + machine.id);
    if (mmContainerEl && !mmContainerEl.classList.contains('mm-inline-fullscreen')) {
      /* Trigger the fullscreen open via the FS button handler so scroll
         position is saved/restored consistently */
      const fsBtn = mmContainerEl.querySelector('#mm-fs-' + machine.id);
      if (fsBtn) fsBtn.click();
    }
  });

  /* --- Sidebar modal buttons --- */
  document.getElementById('openCredModalTab')?.addEventListener('click', () => openCredAllModal(machine));
  document.getElementById('openFindingsModalTab')?.addEventListener('click', () => openFindingsModal(machine));
  document.getElementById('openEvidenceModalTab')?.addEventListener('click', () => openEvidenceModal(machine));
  document.getElementById('openDocumentationTab')?.addEventListener('click', () => openDocsModal());
  document.getElementById('openChecklistTab')?.addEventListener('click', () => openChecklistModal(machine));
  document.getElementById('openAiDocumentationTab')?.addEventListener('click', () => openAiDocsModal());

  /* --- Wire notes workspace --- */
  wireNotesWorkspace(machine);


  document.getElementById('backToDashboard').addEventListener('click', () => {
    window.location.hash = '#/';
  });

  document.getElementById('machineStatus').addEventListener('change', (event) => {
    const previous = machine.status;
    machine.status = event.target.value;
    const prevLabel = statusConfig[previous]?.label || previous;
    const newLabel = statusConfig[machine.status]?.label || machine.status;
    addActivity('updated_machine', `Status changed for ${machine.ip}: ${prevLabel} → ${newLabel}`, machine.id);
    mount();
  });

  /* --- Click IP to copy --- */
  document.querySelectorAll('[data-copy-ip]').forEach(el => {
    el.addEventListener('click', async () => {
      await navigator.clipboard.writeText(machine.ip);
      showCopyFeedback(el, 'Copied!');
    });
  });

  /* --- Inline edit buttons for IP / OS / Domain --- */
  document.querySelectorAll('[data-edit-field]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const field = btn.dataset.editField;

      if (field === 'ip') {
        const val = window.prompt('Edit IP Address', machine.ip);
        if (val && val.trim() && val.trim() !== machine.ip) {
          const old = machine.ip;
          machine.ip = val.trim();
          addActivity('updated_machine', `Changed IP: ${old} → ${machine.ip}`, machine.id);
          persist(); mount();
        }
      } else if (field === 'os_type') {
        const current = machine.os_type === 'windows' ? 'Windows' : 'Linux';
        const next = machine.os_type === 'windows' ? 'linux' : 'windows';
        const nextLabel = next === 'windows' ? 'Windows' : 'Linux';
        if (window.confirm(`Switch OS from ${current} to ${nextLabel}?`)) {
          machine.os_type = next;
          addActivity('updated_machine', `Changed OS: ${current} → ${nextLabel}`, machine.id);
          persist(); mount();
        }
      } else if (field === 'hostname') {
        const val = window.prompt('Edit Domain Name', machine.hostname || '');
        if (val !== null) {
          const old = machine.hostname || '-';
          machine.hostname = val.trim();
          addActivity('updated_machine', `Changed domain: ${old} → ${machine.hostname || '-'}`, machine.id);
          persist(); mount();
        }
      }
    });
  });



  /* --- Mind map heading jump clicks --- */
  const mmContainer = document.getElementById('mm-container-' + machine.id);
  if (mmContainer) wireMMHeadingJumps(machine, mmContainer);
  if (mmContainer) wireFsBlockDrag(mmContainer, machine);

}

/** Wire credential CRUD: add form toggle/submit, delete with confirm, reveal toggle. */
function wireMachineCredentials(machine) {
  document.getElementById('openMachineCredForm')?.addEventListener('click', () => {
    state.ui.showAddMachineCred = true;
    mount();
  });

  document.getElementById('cancelMachineCredForm')?.addEventListener('click', () => {
    state.ui.showAddMachineCred = false;
    mount();
  });

  document.getElementById('submitMachineCredForm')?.addEventListener('click', () => {
    const username = document.getElementById('mcUsername').value.trim();
    const password = document.getElementById('mcPassword').value;
    const service = document.getElementById('mcService').value.trim();
    const credType = document.getElementById('mcType').value;
    if (!username) return;

    state.credentials.unshift({
      id: uid('c'),
      machine_id: machine.id,
      username,
      password,
      service,
      cred_type: credType,
      created_at: nowStamp(),
    });

    addActivity('added_credential', `Added credential: ${username} (${service || credType})`, machine.id);
    state.ui.showAddMachineCred = false;
    mount();
  });

  document.querySelectorAll('[data-machine-cred-action]').forEach((button) => {
    button.addEventListener('click', async () => {
      const id = button.dataset.id;
      const action = button.dataset.machineCredAction;
      const credential = state.credentials.find((entry) => entry.id === id);
      if (!credential) return;

      if (action === 'reveal') {
        state.reveal[id] = !state.reveal[id];
        mount();
        return;
      }

      if (action === 'copy') {
        await navigator.clipboard.writeText(credential.password || '');
        showCopyFeedback(button, 'Copied!');
        return;
      }

      if (action === 'edit') {
        openCredEditModal(credential.id);
        return;
      }

      if (action === 'delete') {
        if (!armConfirmButton(button)) return;
        state.credentials = state.credentials.filter((entry) => entry.id !== id);
        addActivity('updated_machine', `Deleted credential ${credential.username} (${credential.service || credential.cred_type})`, machine.id);
        mount();
      }
    });
  });
}

/**
 * Wire the inline findings form: add form toggle/submit with evidence buffer
 * management, edit/view/delete buttons, individual evidence CRUD.
 */
function wireFindings(machine) {
  function renderFindingEvidenceBuffer() {
    const list = document.getElementById('findingEvidenceList');
    if (!list) return;
    if (!findingEvidenceBuffer.length) {
      list.innerHTML = '';
      return;
    }

    list.innerHTML = findingEvidenceBuffer.map((file, index) => `
      <div class="evidence-row">
        <span class="small">${file.name}</span>
        <button class="icon-btn" data-remove-finding-buffer="${index}" type="button" title="Remove">🗑</button>
      </div>
    `).join('');

    list.querySelectorAll('[data-remove-finding-buffer]').forEach((button) => {
      button.addEventListener('click', () => {
        const index = Number(button.dataset.removeFindingBuffer);
        if (Number.isNaN(index)) return;
        findingEvidenceBuffer.splice(index, 1);
        renderFindingEvidenceBuffer();
      });
    });
  }

  function addFindingEvidenceFiles(files) {
    const imageFiles = getImageFilesFromList(files);
    if (!imageFiles.length) return;
    findingEvidenceBuffer.push(...imageFiles);
    renderFindingEvidenceBuffer();
  }

  findingEvidenceBuffer = [];

  document.getElementById('openFindingForm')?.addEventListener('click', () => {
    state.ui.showAddFinding = true;
    findingEvidenceBuffer = [];
    mount();
  });

  document.getElementById('cancelFindingForm')?.addEventListener('click', () => {
    state.ui.showAddFinding = false;
    findingEvidenceBuffer = [];
    mount();
  });

  const findingInput = document.getElementById('findingEvidence');
  const findingDrop = document.getElementById('findingEvidenceDrop');
  wireDropzone(findingDrop, findingInput, addFindingEvidenceFiles);

  renderFindingEvidenceBuffer();

  wirePhaseParentSync(document, 'findingPhase', 'findingParentId', machine.id, new Set(), null, machine);

  document.getElementById('submitFindingForm')?.addEventListener('click', async () => {
    const title = document.getElementById('findingTitle').value.trim();
    if (!title) return;

    const evidenceFiles = [...findingEvidenceBuffer];
    const evidence = [];
    for (const file of evidenceFiles) {
      const stored = await putEvidenceFile(file);
      evidence.push(stored);
    }

    const finding = {
      id: uid('f'),
      machine_id: machine.id,
      title,
      description: document.getElementById('findingDescription').value,
      severity: document.getElementById('findingSeverity').value,
      phase: document.getElementById('findingPhase').value,
      parent_id: document.getElementById('findingParentId')?.value || null,
      category: 'finding',
      evidence,
      created_at: nowStamp(),
      updated_at: nowStamp(),
    };

    state.findings.unshift(finding);
    addActivity('added_finding', `Added finding: ${finding.title} [${finding.severity.toUpperCase()} | ${finding.phase}] with ${evidence.length} evidence file(s)`, machine.id);
    state.ui.showAddFinding = false;
    findingEvidenceBuffer = [];
    mount();
  });

  document.querySelectorAll('[data-delete-finding]').forEach((button) => {
    button.addEventListener('click', async () => {
      if (!armConfirmButton(button)) return;
      const id = button.dataset.deleteFinding;
      const finding = state.findings.find((entry) => entry.id === id);
      if (!finding) return;

      const archivedCreds = archiveFindingData(machine, finding, 'finding_deleted_manually');

      state.findings = state.findings.filter((entry) => entry.id !== id);
      const archivedCount = (finding.evidence || []).length + archivedCreds;
      addActivity('updated_machine', `Deleted finding: ${finding.title}${archivedCount ? `. Archived ${archivedCount} item(s).` : ''}`, machine.id);
      persist();
      mount();
    });
  });

  document.querySelectorAll('[data-open-finding-evidence]').forEach((button) => {
    button.addEventListener('click', () => openEvidencePreview(button.dataset.openFindingEvidence));
  });

  document.querySelectorAll('[data-delete-finding-evidence]').forEach((button) => {
    button.addEventListener('click', async () => {
      if (!armConfirmButton(button)) return;
      const findingId = button.dataset.findingId;
      const evidenceId = button.dataset.deleteFindingEvidence;
      const finding = state.findings.find((entry) => entry.id === findingId);
      if (!finding) return;
      const file = (finding.evidence || []).find((entry) => entry.id === evidenceId);
      await deleteEvidenceFile(evidenceId);
      finding.evidence = (finding.evidence || []).filter((file) => file.id !== evidenceId);
      addActivity('updated_machine', `Removed finding evidence from ${finding.title}: ${file?.name || evidenceId}`, machine.id);
      mount();
    });
  });

  document.querySelectorAll('[data-rename-finding-evidence]').forEach((button) => {
    button.addEventListener('click', async () => {
      const findingId = button.dataset.findingId;
      const evidenceId = button.dataset.renameFindingEvidence;
      const finding = state.findings.find((entry) => entry.id === findingId);
      if (!finding) return;
      const file = (finding.evidence || []).find((entry) => entry.id === evidenceId);
      if (!file) return;
      const nextName = window.prompt('Rename evidence file', file.name || 'evidence.png');
      if (!nextName || !nextName.trim()) return;
      const cleanName = nextName.trim();
      file.name = cleanName;
      await updateEvidenceRecordName(evidenceId, cleanName);
      addActivity('updated_machine', `Renamed finding evidence on ${finding.title} to ${cleanName}`, machine.id);
      mount();
    });
  });

  /* --- Mind map finding clicks are wired in wireMachineDetail --- */

  /* --- Edit finding buttons (findings tab) --- */
  document.querySelectorAll('[data-edit-finding]').forEach((button) => {
    button.addEventListener('click', () => openFindingEditModal(button.dataset.editFinding));
  });
}

/* ═══════════════════════════════════════════════
   Finding View Modal (mind map click → view → optional edit)
   ═══════════════════════════════════════════════ */
/* ───────────────────────────────────────────────
  26. Modal Functions
   Full-page dialog overlays for viewing, editing, and managing data.
   Each function builds its HTML, calls showDialogSafely(), and wires
   event handlers inside the modal.
   ─────────────────────────────────────────────── */

/**
 * Open the finding view/edit modal.
 * Supports two modes:
 * • View mode: read-only display with evidence gallery and credential links.
 * • Edit mode: inline editing of all fields with evidence add/remove/rename
 *   and credential link/unlink/create.
 */
function openFindingViewModal(findingId) {
  const finding = state.findings.find(f => f.id === findingId);
  if (!finding) return;
  const modal = document.getElementById('findingViewModal');
  const container = document.getElementById('findingViewContent');

  let fvmEvidenceBuffer = [];
  let fvmRemovedEvidenceIds = new Set();
  let fvmRenamedEvidenceNames = new Map();

  function renderView(editing) {
    if (editing) {
      fvmEvidenceBuffer = [];
      fvmRemovedEvidenceIds = new Set();
      fvmRenamedEvidenceNames = new Map();
      const existingEvidence = (finding.evidence || []);

      const excludeIds = new Set(getDescendantIds(finding.id, state.findings));
      const createdText = formatDateTimeMilitary(finding.created_at);
      const changedText = formatDateTimeMilitary(finding.updated_at || finding.created_at);
      const parentOptsHtml = parentFindingOptionsHtml(finding.machine_id, finding.phase, excludeIds, finding.parent_id, machineById(finding.machine_id));

      container.innerHTML = `
        <div class="finding-modal-header">
          <div class="finding-modal-title-row">
            <h2 style="margin:0">Edit Finding</h2>
          </div>
          <div class="finding-modal-meta">
            <div class="finding-modal-meta-row"><span>Creation:</span><strong>${createdText}</strong></div>
            <div class="finding-modal-meta-row"><span>Last Changed:</span><strong>${changedText}</strong></div>
          </div>
        </div>
        <label>Title *<input id="fvmTitle" value="${(finding.title || '').replace(/"/g, '&quot;')}" /></label>
        <label>Description<textarea id="fvmDesc" rows="24" style="width:100%;margin-top:.4rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem">${(finding.description || '').replace(/</g, '&lt;')}</textarea></label>
        <div class="split">
          <label>Severity
            <select id="fvmSev">
              ${severityOptionsHtml(finding.severity)}
            </select>
          </label>
          <label>Phase
            <select id="fvmPhase">
              ${phaseOptionsHtml(checklistPhaseCatalogForMachine(machineById(finding.machine_id)), finding.phase)}
            </select>
          </label>
        </div>
        <label>Parent Finding
          <select id="fvmParentId">
            <option value="">Root Level (no parent)</option>
            ${parentOptsHtml}
          </select>
        </label>
        <div class="finding-cred-box">
          <div class="small dim" style="margin-bottom:.35rem">Credentials linked to this finding</div>
          <div id="fvmLinkedCreds" class="finding-cred-links"></div>
          <div class="cred-action-prompt">
            <button type="button" class="btn btn-ghost" id="fvmShowLinkCred">Link Credential</button>
            <button type="button" class="btn btn-ghost" id="fvmShowCreateCred">Create New Credential</button>
          </div>
          <div id="fvmLinkCredSection" style="display:none">
            <label style="margin-top:.55rem">Link Existing Credential
              <select id="fvmLinkCredSelect"></select>
            </label>
          </div>
          <div id="fvmCreateCredSection" style="display:none">
            <div class="split" style="margin-top:.3rem">
              <label>Username *<input id="fvmNewCredUser" placeholder="admin" /></label>
              <label>Service<input id="fvmNewCredSvc" placeholder="SSH" /></label>
            </div>
            <div class="split" style="margin-top:.3rem">
              <label>Password / Hash<input id="fvmNewCredPass" /></label>
              <label>Type
                <select id="fvmNewCredType">
                  ${credTypeOptionsHtml()}
                </select>
              </label>
            </div>
            <div style="display:flex;justify-content:flex-end;margin-top:.35rem">
              <button type="button" class="btn btn-primary" id="fvmCreateLinkCred">Create & Link</button>
            </div>
          </div>
        </div>
        <div style="margin-top:.6rem">
          <div class="small dim" style="margin-bottom:.3rem">Evidence</div>
          <input id="fvmEvidenceInput" type="file" accept="image/*" multiple style="display:none">
          <div class="evidence-dropzone" id="fvmEvidenceDrop" tabindex="0">Drop screenshots here or click and press Ctrl+V to paste</div>
          ${existingEvidence.length ? `
            <div class="small dim" style="margin-top:.5rem;margin-bottom:.2rem">Existing</div>
            <div class="evidence-list" id="fvmExistingEvidence">
              ${existingEvidence.map(file => `
                <div class="evidence-row" data-fvm-existing="${file.id}">
                  <button class="btn btn-ghost evidence-open" data-fvm-open-evidence="${file.id}" type="button">${file.name}</button>
                  <div class="evidence-actions">
                    <button class="icon-btn" data-fvm-rename-evidence="${file.id}" type="button" title="Rename">Rename</button>
                    <button class="icon-btn" data-fvm-delete-evidence="${file.id}" type="button" title="Delete">Delete</button>
                  </div>
                </div>
              `).join('')}
            </div>
          ` : ''}
          <div class="evidence-list" id="fvmNewEvidenceList"></div>
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" id="fvmCancel">Cancel</button>
          <button class="btn btn-primary" id="fvmSave">Save</button>
        </div>
      `;

      function renderFvmBuffer() {
        const list = document.getElementById('fvmNewEvidenceList');
        if (!list) return;
        if (!fvmEvidenceBuffer.length) { list.innerHTML = ''; return; }
        list.innerHTML = '<div class="small dim" style="margin-bottom:.2rem">New</div>' + fvmEvidenceBuffer.map((file, i) => `
          <div class="evidence-row">
            <span class="small">${file.name}</span>
            <button class="icon-btn" data-fvm-remove-buffer="${i}" type="button" title="Remove">🗑</button>
          </div>
        `).join('');
        list.querySelectorAll('[data-fvm-remove-buffer]').forEach(btn => {
          btn.addEventListener('click', () => {
            fvmEvidenceBuffer.splice(Number(btn.dataset.fvmRemoveBuffer), 1);
            renderFvmBuffer();
          });
        });
      }

      function addFvmFiles(files) {
        const imageFiles = getImageFilesFromList(files);
        if (!imageFiles.length) return;
        fvmEvidenceBuffer.push(...imageFiles);
        renderFvmBuffer();
      }

      wirePhaseParentSync(container, 'fvmPhase', 'fvmParentId', finding.machine_id, excludeIds, finding.parent_id, machineById(finding.machine_id));

      // Dropzone
      const fvmInput = container.querySelector('#fvmEvidenceInput');
      const fvmDrop = container.querySelector('#fvmEvidenceDrop');
      wireDropzone(fvmDrop, fvmInput, addFvmFiles);

      // Open existing evidence
      container.querySelectorAll('[data-fvm-open-evidence]').forEach(btn => {
        btn.addEventListener('click', () => openEvidencePreview(btn.dataset.fvmOpenEvidence));
      });

      // Delete existing evidence
      container.querySelectorAll('[data-fvm-rename-evidence]').forEach(btn => {
        btn.addEventListener('click', () => {
          const evId = btn.dataset.fvmRenameEvidence;
          const file = (finding.evidence || []).find(entry => entry.id === evId);
          if (!file) return;
          const nextName = window.prompt('Rename evidence file', file.name || 'evidence.png');
          if (!nextName || !nextName.trim()) return;
          const cleanName = nextName.trim();
          file.name = cleanName;
          fvmRenamedEvidenceNames.set(evId, cleanName);
          const fileBtn = container.querySelector('[data-fvm-open-evidence="' + evId + '"]');
          if (fileBtn) fileBtn.textContent = cleanName;
        });
      });

      container.querySelectorAll('[data-fvm-delete-evidence]').forEach(btn => {
        btn.addEventListener('click', () => {
          const evId = btn.dataset.fvmDeleteEvidence;
          fvmRemovedEvidenceIds.add(evId);
          fvmRenamedEvidenceNames.delete(evId);
          const row = container.querySelector('[data-fvm-existing="' + evId + '"]');
          if (row) row.remove();
        });
      });

      // Credential section: prompt toggle logic
      function refreshFvmCredentialSection() {
        const linkedHost = container.querySelector('#fvmLinkedCreds');
        const select = container.querySelector('#fvmLinkCredSelect');
        if (!linkedHost || !select) return;
        const creds = machineCredentials(finding.machine_id);
        const linked = creds.filter(c => c.finding_id === finding.id);
        linkedHost.innerHTML = linked.length
          ? linked.map(c => `
            <div class="finding-cred-row">
              <span class="mono">${(c.username || '').replace(/</g, '&lt;')}</span>
              <span class="small dim">${(c.service || c.cred_type || '').replace(/</g, '&lt;')}</span>
              <button type="button" class="icon-btn" data-fvm-unlink-cred="${c.id}" title="Unlink">×</button>
            </div>
          `).join('')
          : '<div class="small dim">No linked credentials.</div>';
        const options = creds
          .filter(c => !c.finding_id || c.finding_id === finding.id)
          .map(c => `<option value="${c.id}">${c.username}${c.service ? ` (${c.service})` : ''}</option>`)
          .join('');
        select.innerHTML = '<option value="">Select credential</option>' + options;
        select.addEventListener('change', () => {
          const credId = select.value;
          if (!credId) return;
          const cred = state.credentials.find(c => c.id === credId);
          if (!cred) return;
          cred.finding_id = finding.id;
          finding.updated_at = nowStamp();
          addActivity('updated_machine', `Linked credential "${cred.username}" to finding "${finding.title}"`, finding.machine_id);
          persist();
          refreshFvmCredentialSection();
        });
        linkedHost.querySelectorAll('[data-fvm-unlink-cred]').forEach(btn => {
          btn.addEventListener('click', () => {
            const cred = state.credentials.find(c => c.id === btn.dataset.fvmUnlinkCred);
            if (!cred) return;
            cred.finding_id = null;
            finding.updated_at = nowStamp();
            addActivity('updated_machine', `Unlinked credential "${cred.username}" from finding "${finding.title}"`, finding.machine_id);
            persist();
            refreshFvmCredentialSection();
          });
        });
      }

      container.querySelector('#fvmShowLinkCred')?.addEventListener('click', () => {
        const linkSec = container.querySelector('#fvmLinkCredSection');
        const createSec = container.querySelector('#fvmCreateCredSection');
        const linkBtn = container.querySelector('#fvmShowLinkCred');
        const createBtn = container.querySelector('#fvmShowCreateCred');
        if (linkSec.style.display === 'none') {
          linkSec.style.display = '';
          createSec.style.display = 'none';
          linkBtn.classList.add('active');
          createBtn.classList.remove('active');
        } else {
          linkSec.style.display = 'none';
          linkBtn.classList.remove('active');
        }
      });

      container.querySelector('#fvmShowCreateCred')?.addEventListener('click', () => {
        const linkSec = container.querySelector('#fvmLinkCredSection');
        const createSec = container.querySelector('#fvmCreateCredSection');
        const linkBtn = container.querySelector('#fvmShowLinkCred');
        const createBtn = container.querySelector('#fvmShowCreateCred');
        if (createSec.style.display === 'none') {
          createSec.style.display = '';
          linkSec.style.display = 'none';
          createBtn.classList.add('active');
          linkBtn.classList.remove('active');
        } else {
          createSec.style.display = 'none';
          createBtn.classList.remove('active');
        }
      });

      container.querySelector('#fvmCreateLinkCred')?.addEventListener('click', () => {
        const username = container.querySelector('#fvmNewCredUser')?.value.trim();
        if (!username) { container.querySelector('#fvmNewCredUser')?.focus(); return; }
        const credential = {
          id: uid('c'),
          machine_id: finding.machine_id,
          username,
          password: container.querySelector('#fvmNewCredPass')?.value || '',
          cred_type: container.querySelector('#fvmNewCredType')?.value || 'plain',
          service: container.querySelector('#fvmNewCredSvc')?.value || '',
          finding_id: finding.id,
          created_at: nowStamp(),
        };
        state.credentials.unshift(credential);
        finding.updated_at = nowStamp();
        addActivity('added_credential', `Added credential: ${credential.username} (${credential.service || credential.cred_type})`, credential.machine_id);
        addActivity('updated_machine', `Linked credential "${credential.username}" to finding "${finding.title}"`, finding.machine_id);
        container.querySelector('#fvmNewCredUser').value = '';
        container.querySelector('#fvmNewCredPass').value = '';
        container.querySelector('#fvmNewCredSvc').value = '';
        container.querySelector('#fvmNewCredType').value = 'plain';
        persist();
        refreshFvmCredentialSection();
      });

      refreshFvmCredentialSection();

      container.querySelector('#fvmCancel').addEventListener('click', () => renderView(false));
      container.querySelector('#fvmSave').addEventListener('click', async () => {
        const title = document.getElementById('fvmTitle').value.trim();
        if (!title) return;
        finding.title = title;
        finding.description = document.getElementById('fvmDesc').value;
        finding.severity = document.getElementById('fvmSev').value;
        finding.phase = document.getElementById('fvmPhase').value;
        finding.parent_id = document.getElementById('fvmParentId').value || null;
        finding.updated_at = nowStamp();

        for (const [evId, newName] of fvmRenamedEvidenceNames.entries()) {
          if (!fvmRemovedEvidenceIds.has(evId)) {
            await updateEvidenceRecordName(evId, newName);
          }
        }

        for (const evId of fvmRemovedEvidenceIds) {
          await deleteEvidenceFile(evId);
        }

        // Store new evidence files
        const newEvidence = [];
        for (const file of fvmEvidenceBuffer) {
          const stored = await putEvidenceFile(file);
          newEvidence.push(stored);
        }

        // Merge: keep existing (minus removed) + add new
        finding.evidence = [
          ...(finding.evidence || []).filter(f => !fvmRemovedEvidenceIds.has(f.id)),
          ...newEvidence,
        ];

        const totalAdded = newEvidence.length;
        const totalRemoved = fvmRemovedEvidenceIds.size;
        let evidenceNote = '';
        if (totalAdded || totalRemoved) {
          const parts = [];
          if (totalAdded) parts.push('+' + totalAdded + ' evidence');
          if (totalRemoved) parts.push('-' + totalRemoved + ' evidence');
          evidenceNote = ' (' + parts.join(', ') + ')';
        }
        addActivity('updated_machine', 'Edited finding: ' + finding.title + ' [' + finding.severity.toUpperCase() + ' | ' + finding.phase + ']' + evidenceNote, finding.machine_id);
        modal.close();
        mount();
      });
    } else {
      const sevBadge = severityClass[finding.severity] || 'severity-info';
      const createdText = formatDateTimeMilitary(finding.created_at);
      const changedText = formatDateTimeMilitary(finding.updated_at || finding.created_at);
      container.innerHTML = `
        <div class="finding-modal-header">
          <div class="finding-modal-title-row">
            <span class="sev-badge ${sevBadge}">${finding.severity.toUpperCase()}</span>
            <h2 style="margin:0;font-size:1.1rem">${finding.title}</h2>
            <span class="badge">${finding.phase}</span>
          </div>
          <div class="finding-modal-meta">
            <div class="finding-modal-meta-row"><span>Creation:</span><strong>${createdText}</strong></div>
            <div class="finding-modal-meta-row"><span>Last Changed:</span><strong>${changedText}</strong></div>
          </div>
        </div>
        ${finding.description ? `<p style="margin:.65rem 0;color:var(--muted)">${finding.description}</p>` : '<p class="dim small" style="margin:.65rem 0">No description</p>'}
        ${(finding.evidence || []).length ? `
          <div style="margin:.5rem 0">
            <p class="small dim" style="margin-bottom:.3rem">Evidence</p>
            ${(finding.evidence || []).map(file => `
              <div class="evidence-row"><button class="btn btn-ghost evidence-open" data-modal-evidence="${file.id}" type="button">${file.name}</button></div>
            `).join('')}
          </div>
        ` : ''}
        <div class="modal-actions">
          <button class="btn btn-ghost" id="fvmClose">Close</button>
          <button class="btn btn-primary" id="fvmEdit">Edit</button>
        </div>
      `;
      container.querySelector('#fvmClose').addEventListener('click', () => modal.close());
      container.querySelector('#fvmEdit').addEventListener('click', () => renderView(true));
      container.querySelectorAll('[data-modal-evidence]').forEach(btn => {
        btn.addEventListener('click', () => openEvidencePreview(btn.dataset.modalEvidence));
      });
    }
  }

  renderView(false);
  showDialogSafely(modal);
  addBackdropClose(modal);
}

/* ═══════════════════════════════════════════════
   Findings Modal
   ═══════════════════════════════════════════════ */
/**
 * Open the “All Findings” modal with phase-tab navigation, add-finding form,
 * and an archived findings section with restore/permanent-delete options.
 */
function openFindingsModal(machine) {
  const modal = document.getElementById('findingsModal');
  const container = document.getElementById('findingsModalContent');
  if (!modal || !container) return;

  const machinePhases = checklistPhaseCatalogForMachine(machine);
  const PHASE_DEFS = [
    { id: 'all', label: 'Default' },
    ...machinePhases.map((phase) => ({
      id: phase.id,
      label: phase.id === 'osint'
        ? 'OSINT'
        : phase.id === 'recon'
          ? 'Enumeration'
          : phase.id === 'post_exploitation'
            ? 'Post-Exploit'
            : phase.name,
    })),
  ];

  let showForm = false;
  let evidenceBuffer = [];

  function renderFindingEvidenceBufferList() {
    const list = container.querySelector('#fmEvidenceList');
    if (!list) return;
    list.innerHTML = evidenceBuffer.map((file, i) => `
      <div class="evidence-row">
        <span class="small">${file.name}</span>
        <button class="icon-btn" data-rm-buf="${i}" type="button" title="Remove">🗑</button>
      </div>
    `).join('');
    list.querySelectorAll('[data-rm-buf]').forEach(btn => {
      btn.addEventListener('click', () => { evidenceBuffer.splice(Number(btn.dataset.rmBuf), 1); renderFindingEvidenceBufferList(); });
    });
  }

  function addToEvidenceBuffer(files) {
    const imgs = getImageFilesFromList(files);
    if (!imgs.length) return;
    evidenceBuffer.push(...imgs);
    renderFindingEvidenceBufferList();
  }

  function renderContent() {
    const findings = machineFindings(machine.id);
    const activePhaseRaw = state.ui.mmPhase || 'all';
    const activePhase = PHASE_DEFS.some((phaseDef) => phaseDef.id === activePhaseRaw) ? activePhaseRaw : 'all';
    const filteredFindings = activePhase === 'all'
      ? findings
      : findings.filter((finding) => (finding.phase || 'unknown') === activePhase);
    const activePhaseName = activePhase === 'all'
      ? 'All Phases'
      : (machinePhases.find((phase) => phase.id === activePhase)?.name || activePhase);

    container.innerHTML = `
      <div class="fm-header">
        <h2>Findings <span class="badge">${filteredFindings.length}</span></h2>
        <button class="btn btn-ghost" id="fmClose">✕</button>
      </div>
      <div class="fm-body">
        <div class="fm-toolbar">
          <button class="btn btn-primary btn-sm" id="fmAddBtn">+ Add Finding</button>
        </div>
        <div class="mm-phase-tabs fm-phase-tabs" style="margin-bottom:.7rem">
          ${PHASE_DEFS.map((phaseDef) => `
            <button class="mm-phase-btn${activePhase === phaseDef.id ? ' mm-phase-btn--active' : ''}${phaseDef.id === 'all' ? ' mm-phase-btn--all' : ''}" data-fm-phase="${phaseDef.id}">${phaseDef.label}</button>
          `).join('')}
        </div>
        ${showForm ? `
          <div class="inline-form card" style="margin-bottom:1rem">
            <label>Title *<input id="fmTitle" placeholder="Apache 2.4.49 Path Traversal"></label>
            <label>Description<textarea id="fmDesc" rows="24" style="width:100%;margin-top:.4rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem"></textarea></label>
            <div class="split">
              <label>Severity
                <select id="fmSeverity">
                  ${severityOptionsHtml('high')}
                </select>
              </label>
              <label>Phase
                <select id="fmPhase">${phaseOptionsHtml(machinePhases)}</select>
              </label>
            </div>
            <label>Parent Finding
              <select id="fmParent">
                <option value="">Root Level (no parent)</option>
                ${parentFindingOptionsHtml(machine.id, machinePhases[0]?.id || '', new Set(), null, machine)}
              </select>
            </label>
            <input id="fmEvidenceInput" type="file" accept="image/*" multiple style="display:none">
            <div class="evidence-dropzone" id="fmEvidenceDrop" tabindex="0">Drop screenshots here or click / Ctrl+V to paste</div>
            <div class="evidence-list" id="fmEvidenceList"></div>
            <div class="modal-actions">
              <button class="btn btn-ghost" id="fmCancelForm">Cancel</button>
              <button class="btn btn-primary" id="fmSubmitForm">Add Finding</button>
            </div>
          </div>
        ` : ''}
        ${!filteredFindings.length ? `<p class="small dim" style="padding:1rem;text-align:center">No findings documented for ${activePhaseName}.</p>` : `
          <div class="finding-list">
            ${(() => {
              if (activePhase !== 'all') {
                return buildFindingCards(filteredFindings, null, 0);
              }
              const knownPhases = machinePhases.map((phase) => phase.id);
              let html = knownPhases.map(pid => {
                const phase = machinePhases.find(p => p.id === pid);
                const phaseFindings = findings.filter(f => (f.phase || 'unknown') === pid);
                if (!phaseFindings.length) return '';
                const pColor = phaseColor(pid);
                return `
                  <div class="fm-phase-group">
                    <div class="fm-phase-header" style="--phase-col:${pColor}">
                      <span class="fm-phase-dot" style="background:${pColor}"></span>
                      <span class="fm-phase-name">${phase ? phase.name : pid}</span>
                      <span class="badge" style="background:${pColor}22;color:${pColor};border-color:${pColor}55">${phaseFindings.length}</span>
                    </div>
                    ${buildFindingCards(phaseFindings, null, 0)}
                  </div>
                `;
              }).join('');
              const otherFindings = findings.filter(f => !knownPhases.includes(f.phase || 'unknown'));
              if (otherFindings.length) {
                html += `
                  <div class="fm-phase-group">
                    <div class="fm-phase-header" style="--phase-col:var(--text)">
                      <span class="fm-phase-dot" style="background:var(--muted)"></span>
                      <span class="fm-phase-name">Other</span>
                      <span class="badge">${otherFindings.length}</span>
                    </div>
                    ${buildFindingCards(otherFindings, null, 0)}
                  </div>
                `;
              }
              return html;
            })()}
          </div>
        `}
        ${(() => {
          const archEv = machine.archived_evidence || [];
          const archCr = machine.archived_credentials || [];
          if (!archEv.length && !archCr.length) return '';
          return `
            <div class="fm-archived-section">
              <div class="fm-archived-header" id="fmArchivedToggle">
                <span class="fm-archived-icon">📦</span>
                <span>Archived</span>
                <span class="badge" style="background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)">${archEv.length + archCr.length}</span>
                <span class="fm-archived-chevron">▸</span>
              </div>
              <div class="fm-archived-body" style="display:none">
                ${archEv.length ? `
                  <div class="fm-archived-group">
                    <div class="fm-archived-group-label">📓 Archived Evidence (${archEv.length})</div>
                    ${archEv.map(ev => `
                      <div class="finding-card" style="border-color:rgba(234,179,8,.25)">
                        <div class="finding-main">
                          <div class="finding-head">
                            <span class="badge" style="background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)">Archived</span>
                            <span class="small dim">from: ${ev.source_finding_title || 'Unknown finding'}</span>
                          </div>
                          <div class="evidence-list" style="margin-top:.35rem">
                            <div class="evidence-row">
                              <button class="btn btn-ghost evidence-open" data-archived-ev-open="${ev.id}" type="button">📄 ${ev.name}</button>
                            </div>
                          </div>
                        </div>
                        <div class="finding-actions">
                          <button class="icon-btn" data-delete-archived-ev="${ev.id}" title="Permanently Delete">🗑</button>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                ` : ''}
                ${archCr.length ? `
                  <div class="fm-archived-group">
                    <div class="fm-archived-group-label">🔑 Archived Credentials (${archCr.length})</div>
                    ${archCr.map(c => `
                      <div class="finding-card" style="border-color:rgba(234,179,8,.25)">
                        <div class="finding-main">
                          <div class="finding-head">
                            <span class="badge" style="background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)">Archived</span>
                            <span class="small dim">from: ${c.source_finding_title || 'Unknown finding'}</span>
                          </div>
                          <div style="margin-top:.35rem">
                            <span class="small"><strong>${c.username}</strong> ${c.service ? `· ${c.service}` : ''} ${c.cred_type ? `(${c.cred_type})` : ''}</span>
                          </div>
                        </div>
                        <div class="finding-actions">
                          <button class="icon-btn" data-restore-archived-cred="${c.id}" title="Restore to Active Credentials">↩</button>
                          <button class="icon-btn" data-delete-archived-cred="${c.id}" title="Permanently Delete">🗑</button>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                ` : ''}
              </div>
            </div>
          `;
        })()}
      </div>
    `;

    /* close */
    container.querySelector('#fmClose').addEventListener('click', () => modal.close());

    container.querySelectorAll('[data-fm-phase]').forEach((button) => {
      button.addEventListener('click', () => {
        state.ui.mmPhase = button.dataset.fmPhase;
        const mmContainer = document.getElementById('mm-container-' + machine.id);
        if (mmContainer) {
          refreshMindMapInPlace(machine);
        }
        renderContent();
      });
    });

    /* toggle add form */
    container.querySelector('#fmAddBtn').addEventListener('click', () => {
      showForm = !showForm;
      evidenceBuffer = [];
      renderContent();
    });

    if (showForm) {
      const titleInput = container.querySelector('#fmTitle');
      titleInput?.focus();

      container.querySelector('#fmCancelForm').addEventListener('click', () => { showForm = false; evidenceBuffer = []; renderContent(); });

      const fileInput = container.querySelector('#fmEvidenceInput');
      const dropzone  = container.querySelector('#fmEvidenceDrop');
      wireDropzone(dropzone, fileInput, addToEvidenceBuffer);

      wirePhaseParentSync(container, 'fmPhase', 'fmParent', machine.id, new Set(), null, machine);

      container.querySelector('#fmSubmitForm').addEventListener('click', async () => {
        const title = container.querySelector('#fmTitle').value.trim();
        if (!title) { container.querySelector('#fmTitle').focus(); return; }
        const evidenceFiles = [...evidenceBuffer];
        const evidence = [];
        for (const file of evidenceFiles) { evidence.push(await putEvidenceFile(file)); }
        state.findings.unshift({
          id: uid('f'),
          machine_id: machine.id,
          title,
          description: container.querySelector('#fmDesc').value,
          severity: container.querySelector('#fmSeverity').value,
          phase: container.querySelector('#fmPhase').value,
          parent_id: container.querySelector('#fmParent')?.value || null,
          category: 'finding',
          evidence,
          created_at: nowStamp(),
          updated_at: nowStamp(),
        });
        addActivity('added_finding', `Added finding: ${title} with ${evidence.length} evidence file(s)`, machine.id);
        showForm = false;
        evidenceBuffer = [];
        persist();
        mount();
        renderContent();
      });
    }

    /* delete finding (archives evidence & credentials) */
    container.querySelectorAll('[data-delete-finding]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!armConfirmButton(btn)) return;
        const finding = state.findings.find(f => f.id === btn.dataset.deleteFinding);
        if (!finding) return;

        const archivedCreds = archiveFindingData(machine, finding, 'finding_deleted_manually');

        state.findings = state.findings.filter(f => f.id !== finding.id);
        const archivedCount = (finding.evidence || []).length + archivedCreds;
        addActivity('updated_machine', `Deleted finding: ${finding.title}${archivedCount ? `. Archived ${archivedCount} item(s).` : ''}`, machine.id);
        persist();
        mount();
        renderContent();
      });
    });

    /* edit finding (pencil button) */
    container.querySelectorAll('[data-edit-finding]').forEach(btn => {
      btn.addEventListener('click', () => openFindingEditModal(btn.dataset.editFinding));
    });

    /* open finding evidence files */
    container.querySelectorAll('[data-open-finding-evidence]').forEach(btn => {
      btn.addEventListener('click', () => openEvidencePreview(btn.dataset.openFindingEvidence));
    });

    /* delete finding evidence */
    container.querySelectorAll('[data-delete-finding-evidence]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!armConfirmButton(btn)) return;
        const finding = state.findings.find(f => f.id === btn.dataset.findingId);
        if (!finding) return;
        await deleteEvidenceFile(btn.dataset.deleteFindingEvidence);
        finding.evidence = (finding.evidence || []).filter(f => f.id !== btn.dataset.deleteFindingEvidence);
        finding.updated_at = nowStamp();
        addActivity('updated_machine', `Removed evidence from finding: ${finding.title}`, machine.id);
        persist();
        mount();
        renderContent();
      });
    });

    /* rename finding evidence */
    container.querySelectorAll('[data-rename-finding-evidence]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const finding = state.findings.find(f => f.id === btn.dataset.findingId);
        if (!finding) return;
        const file = (finding.evidence || []).find(f => f.id === btn.dataset.renameFindingEvidence);
        if (!file) return;
        const name = window.prompt('Rename evidence file', file.name || 'evidence.png');
        if (!name?.trim()) return;
        file.name = name.trim();
        finding.updated_at = nowStamp();
        await updateEvidenceRecordName(btn.dataset.renameFindingEvidence, name.trim());
        addActivity('updated_machine', `Renamed evidence on "${finding.title}"`, machine.id);
        persist();
        renderContent();
      });
    });

    /* ── Archived section toggle ── */
    container.querySelector('#fmArchivedToggle')?.addEventListener('click', () => {
      const body = container.querySelector('.fm-archived-body');
      const chevron = container.querySelector('.fm-archived-chevron');
      if (!body) return;
      const isHidden = body.style.display === 'none';
      body.style.display = isHidden ? 'block' : 'none';
      if (chevron) chevron.textContent = isHidden ? '▾' : '▸';
    });

    /* open archived evidence */
    container.querySelectorAll('[data-archived-ev-open]').forEach(btn => {
      btn.addEventListener('click', () => openEvidencePreview(btn.dataset.archivedEvOpen));
    });

    /* permanently delete archived evidence */
    container.querySelectorAll('[data-delete-archived-ev]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const evId = btn.dataset.deleteArchivedEv;
        if (!confirm('Permanently delete this archived evidence file?')) return;
        await deleteEvidenceFile(evId);
        machine.archived_evidence = (machine.archived_evidence || []).filter(e => e.id !== evId);
        addActivity('updated_machine', `Permanently deleted archived evidence: ${evId}`, machine.id);
        persist();
        renderContent();
      });
    });

    /* restore archived credential to active */
    container.querySelectorAll('[data-restore-archived-cred]').forEach(btn => {
      btn.addEventListener('click', () => {
        const credId = btn.dataset.restoreArchivedCred;
        const archCred = (machine.archived_credentials || []).find(c => c.id === credId);
        if (!archCred) return;
        const { archived_at, source_finding_title, source_finding_id, source_type, ...restoredCred } = archCred;
        state.credentials.unshift(restoredCred);
        machine.archived_credentials = machine.archived_credentials.filter(c => c.id !== credId);
        addActivity('updated_machine', `Restored archived credential: ${restoredCred.username}`, machine.id);
        persist();
        renderContent();
      });
    });

    /* permanently delete archived credential */
    container.querySelectorAll('[data-delete-archived-cred]').forEach(btn => {
      btn.addEventListener('click', () => {
        const credId = btn.dataset.deleteArchivedCred;
        if (!confirm('Permanently delete this archived credential?')) return;
        machine.archived_credentials = (machine.archived_credentials || []).filter(c => c.id !== credId);
        addActivity('updated_machine', `Permanently deleted archived credential`, machine.id);
        persist();
        renderContent();
      });
    });
  }

  renderContent();
  showDialogSafely(modal);
  addBackdropClose(modal);
}

/* ═══════════════════════════════════════════════
   Evidence Modal
   ═══════════════════════════════════════════════ */
/**
 * Open the evidence gallery modal, showing all evidence files grouped
 * by checklist phase.  Includes an archived evidence section at the bottom.
 */
function openEvidenceModal(machine) {
  const modal = document.getElementById('evidenceModal');
  const container = document.getElementById('evidenceModalContent');
  if (!modal || !container) return;

  const machinePhases = checklistPhaseCatalogForMachine(machine);

  function itemPhase(itemId) {
    for (const phase of machinePhases) {
      if (phase.items.some(i => i.id === itemId)) return phase.id;
    }
    return 'unknown';
  }

  function itemName(itemId) {
    for (const phase of machinePhases) {
      const item = phase.items.find(i => i.id === itemId);
      if (item) return item.name;
    }
    return itemId;
  }

  function renderContent() {
    const findings = machineFindings(machine.id);
    const evidenceItems = [];

    /* Collect finding evidence */
    findings.forEach(f => {
      (f.evidence || []).forEach(ev => {
        evidenceItems.push({
          id: ev.id,
          name: ev.name,
          phase: f.phase || 'unknown',
          source: 'finding',
          sourceLabel: f.title,
          severity: f.severity,
          findingId: f.id,
        });
      });
    });

    /* Collect checklist item evidence */
    Object.entries(machine.item_evidence || {}).forEach(([itemId, files]) => {
      const phase = itemPhase(itemId);
      files.forEach(ev => {
        evidenceItems.push({
          id: ev.id,
          name: ev.name,
          phase,
          source: 'checklist',
          sourceLabel: itemName(itemId),
          itemId,
        });
      });
    });

    container.innerHTML = `
      <div class="fm-header">
        <h2>📓 Evidence <span class="badge">${evidenceItems.length}</span></h2>
        <button class="btn btn-ghost" id="evmClose">✕</button>
      </div>
      <div class="fm-body">
        ${!evidenceItems.length ? '<p class="small dim" style="padding:1rem;text-align:center">No evidence files yet. Add evidence via Findings or Checklist items.</p>' : `
          <div class="finding-list">
            ${(() => {
              const knownPhases = machinePhases.map((phase) => phase.id);
              let html = knownPhases.map(pid => {
              const phase = machinePhases.find(p => p.id === pid);
              const phaseEvidence = evidenceItems.filter(e => e.phase === pid);
              if (!phaseEvidence.length) return '';
              const pColor = phaseColor(pid);
              return `
                <div class="fm-phase-group">
                  <div class="fm-phase-header" style="--phase-col:${pColor}">
                    <span class="fm-phase-dot" style="background:${pColor}"></span>
                    <span class="fm-phase-name">${phase ? phase.name : pid}</span>
                    <span class="badge" style="background:${pColor}22;color:${pColor};border-color:${pColor}55">${phaseEvidence.length}</span>
                  </div>
                  ${phaseEvidence.map(ev => `
                    <div class="finding-card">
                      <div class="finding-main">
                        <div class="finding-head">
                          <span class="badge">${ev.source === 'finding' ? '🔍 Finding' : '☑ Checklist'}</span>
                          <span class="small dim">${ev.sourceLabel}</span>
                          ${ev.severity ? `<span class="sev-badge ${severityClass[ev.severity] || 'severity-info'}">${ev.severity.toUpperCase()}</span>` : ''}
                        </div>
                        <div class="evidence-list" style="margin-top:.35rem">
                          <div class="evidence-row">
                            <button class="btn btn-ghost evidence-open" data-ev-open="${ev.id}" type="button">📄 ${ev.name}</button>
                          </div>
                        </div>
                      </div>
                    </div>
                  `).join('')}
                </div>
              `;
            }).join('');
              const otherEvidence = evidenceItems.filter(e => !knownPhases.includes(e.phase));
              if (otherEvidence.length) {
                html += `
                  <div class="fm-phase-group">
                    <div class="fm-phase-header" style="--phase-col:var(--text)">
                      <span class="fm-phase-dot" style="background:var(--muted)"></span>
                      <span class="fm-phase-name">Other</span>
                      <span class="badge">${otherEvidence.length}</span>
                    </div>
                    ${otherEvidence.map(ev => `
                      <div class="finding-card">
                        <div class="finding-main">
                          <div class="finding-head">
                            <span class="badge">${ev.source === 'finding' ? '🔍 Finding' : '☑ Checklist'}</span>
                            <span class="small dim">${ev.sourceLabel}</span>
                            ${ev.severity ? `<span class="sev-badge ${severityClass[ev.severity] || 'severity-info'}">${ev.severity.toUpperCase()}</span>` : ''}
                          </div>
                          <div class="evidence-list" style="margin-top:.35rem">
                            <div class="evidence-row">
                              <button class="btn btn-ghost evidence-open" data-ev-open="${ev.id}" type="button">📄 ${ev.name}</button>
                            </div>
                          </div>
                        </div>
                      </div>
                    `).join('')}
                  </div>
                `;
              }
              return html;
            })()}
          </div>
        `}
        ${(() => {
          const archEv = machine.archived_evidence || [];
          if (!archEv.length) return '';
          return `
            <div class="fm-archived-section">
              <div class="fm-archived-header" id="evmArchivedToggle">
                <span class="fm-archived-icon">📦</span>
                <span>Archived Evidence</span>
                <span class="badge" style="background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)">${archEv.length}</span>
                <span class="fm-archived-chevron">▸</span>
              </div>
              <div class="fm-archived-body" id="evmArchivedBody" style="display:none">
                ${archEv.map(ev => `
                  <div class="finding-card" style="border-color:rgba(234,179,8,.25)">
                    <div class="finding-main">
                      <div class="finding-head">
                        <span class="badge" style="background:rgba(234,179,8,.15);color:#eab308;border-color:rgba(234,179,8,.35)">Archived</span>
                        <span class="small dim">from: ${ev.source_finding_title || 'Unknown finding'}</span>
                      </div>
                      <div class="evidence-list" style="margin-top:.35rem">
                        <div class="evidence-row">
                          <button class="btn btn-ghost evidence-open" data-evm-archived-open="${ev.id}" type="button">📄 ${ev.name}</button>
                        </div>
                      </div>
                    </div>
                    <div class="finding-actions">
                      <button class="icon-btn" data-evm-delete-archived="${ev.id}" title="Permanently Delete">🗑</button>
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>
          `;
        })()}
      </div>
    `;

    container.querySelector('#evmClose')?.addEventListener('click', () => modal.close());

    container.querySelectorAll('[data-ev-open]').forEach(btn => {
      btn.addEventListener('click', () => {
        openEvidencePreview(btn.dataset.evOpen);
      });
    });

    /* Archived evidence toggle & actions */
    container.querySelector('#evmArchivedToggle')?.addEventListener('click', () => {
      const body = container.querySelector('#evmArchivedBody');
      const chevron = container.querySelector('#evmArchivedToggle .fm-archived-chevron');
      if (!body) return;
      const isHidden = body.style.display === 'none';
      body.style.display = isHidden ? 'block' : 'none';
      if (chevron) chevron.textContent = isHidden ? '▾' : '▸';
    });

    container.querySelectorAll('[data-evm-archived-open]').forEach(btn => {
      btn.addEventListener('click', () => openEvidencePreview(btn.dataset.evmArchivedOpen));
    });

    container.querySelectorAll('[data-evm-delete-archived]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const evId = btn.dataset.evmDeleteArchived;
        if (!confirm('Permanently delete this archived evidence file?')) return;
        await deleteEvidenceFile(evId);
        machine.archived_evidence = (machine.archived_evidence || []).filter(e => e.id !== evId);
        addActivity('updated_machine', `Permanently deleted archived evidence: ${evId}`, machine.id);
        persist();
        renderContent();
      });
    });
  }

  renderContent();
  showDialogSafely(modal);
  addBackdropClose(modal);
}

/* ═══════════════════════════════════════════════
   Credential Edit Modal
   ═══════════════════════════════════════════════ */
/**
 * Open the “All Credentials” modal showing all credentials for the machine,
 * with add form, finding link/unlink controls, and delete confirmation.
 */
function openCredAllModal(machine) {
  const modal = document.getElementById('credAllModal');
  const container = document.getElementById('credAllContent');
  if (!modal || !container) return;

  let linkingCredId = null;
  let showAddForm = false;
  let pendingDeleteId = null;

  function renderCredRows() {
    const creds = machineCredentials(machine.id);
    const findings = machineFindings(machine.id);

    function findingTitle(fid) {
      if (!fid) return '';
      const f = findings.find(f => f.id === fid);
      return f ? f.title : '(unknown)';
    }

    container.innerHTML = `
      <div class="cred-all-header">
        <h2>🔑 Credentials <span class="badge">${creds.length}</span></h2>
        <div class="cred-all-header-actions">
          <button class="btn btn-primary btn-sm" id="credAllAddToggle">＋ Add Credential</button>
          <button class="btn btn-ghost" id="credAllClose">✕</button>
        </div>
      </div>
      ${showAddForm ? `
        <div class="cred-all-add-form">
          <div class="split">
            <label>Username *<input id="caUsername" placeholder="admin" /></label>
            <label>Service<input id="caService" placeholder="SSH" /></label>
          </div>
          <label>Password / Hash<input id="caPassword" placeholder="" /></label>
          <label>Type
            <select id="caType">
              ${credTypeOptionsHtml()}
            </select>
          </label>
          <div class="modal-actions">
            <button class="btn btn-ghost btn-sm" id="caCancel">Cancel</button>
            <button class="btn btn-primary btn-sm" id="caSubmit">Add Credential</button>
          </div>
        </div>
      ` : ''}
      ${!creds.length && !showAddForm ? '<p class="small dim" style="padding:1rem;text-align:center">No credentials yet.</p>' : `
        <div class="cred-all-list">
          ${creds.map(c => `
            <div class="cred-all-row" data-cred-all-edit="${c.id}">
              <div class="cred-all-main">
                <span class="cred-all-username mono">${c.username}</span>
                <span class="badge">${c.cred_type}</span>
                ${c.service ? `<span class="small dim">${c.service}</span>` : ''}
                ${c.finding_id ? `<span class="cred-finding-badge">🔗 ${findingTitle(c.finding_id)}<button class="cred-unlink-btn" data-cred-unlink="${c.id}" title="Unlink finding">×</button></span>` : ''}
              </div>
              ${linkingCredId === c.id ? `
                <div class="cred-link-select-row">
                  <select class="cred-link-select" data-cred-link-select="${c.id}">
                    <option value="">— choose a finding —</option>
                    ${findings.map(f => `<option value="${f.id}"${f.id === c.finding_id ? ' selected' : ''}>${f.title} [${f.severity}]</option>`).join('')}
                  </select>
                  <button class="btn btn-ghost btn-sm" data-cred-link-cancel="${c.id}">Cancel</button>
                </div>
              ` : ''}
              <div class="cred-all-pw">
                <span class="mono">${state.reveal[c.id] ? (c.password || '—') : '••••••••'}</span>
                <button class="icon-btn" data-cred-all-reveal="${c.id}" title="${state.reveal[c.id] ? 'Hide' : 'Reveal'}">${state.reveal[c.id] ? '🙈' : '👁'}</button>
              </div>
              <div class="cred-all-actions">
                <button class="icon-btn${c.finding_id ? ' active' : ''}" data-cred-all-link="${c.id}" title="${c.finding_id ? 'Change linked finding' : 'Link to Finding'}" type="button">🔗</button>
                <button class="icon-btn" data-cred-all-edit="${c.id}" title="Edit" type="button">✎</button>
                ${pendingDeleteId === c.id
                  ? `<button class="icon-btn cred-delete-confirm" data-cred-confirm-delete="${c.id}" title="Click to confirm" type="button">Sure?</button>`
                  : `<button class="icon-btn" data-cred-all-delete="${c.id}" title="Delete" type="button">🗑</button>`}
              </div>
            </div>
          `).join('')}
        </div>
      `}
    `;

    container.querySelector('#credAllClose')?.addEventListener('click', () => modal.close());

    container.querySelector('#credAllAddToggle')?.addEventListener('click', () => {
      showAddForm = !showAddForm;
      renderCredRows();
      if (showAddForm) document.getElementById('caUsername')?.focus();
    });

    container.querySelector('#caCancel')?.addEventListener('click', () => {
      showAddForm = false;
      renderCredRows();
    });

    container.querySelector('#caSubmit')?.addEventListener('click', () => {
      const username = document.getElementById('caUsername').value.trim();
      if (!username) { document.getElementById('caUsername').focus(); return; }
      const password = document.getElementById('caPassword').value;
      const service = document.getElementById('caService').value.trim();
      const credType = document.getElementById('caType').value;

      state.credentials.unshift({
        id: uid('c'),
        machine_id: machine.id,
        username,
        password,
        service,
        cred_type: credType,
        created_at: nowStamp(),
      });

      addActivity('added_credential', `Added credential: ${username} (${service || credType})`, machine.id);
      showAddForm = false;
      persist();
      renderCredRows();
    });

    container.querySelectorAll('[data-cred-all-reveal]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const id = btn.dataset.credAllReveal;
        state.reveal[id] = !state.reveal[id];
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-all-link]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        linkingCredId = (linkingCredId === btn.dataset.credAllLink) ? null : btn.dataset.credAllLink;
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-link-select]').forEach(sel => {
      sel.addEventListener('change', () => {
        const id = sel.dataset.credLinkSelect;
        const cred = state.credentials.find(c => c.id === id);
        if (!cred) return;
        const fid = sel.value || null;
        cred.finding_id = fid;
        addActivity('updated_machine', fid
          ? `Linked credential "${cred.username}" to finding "${findingTitle(fid)}"`
          : `Unlinked credential "${cred.username}" from finding`, machine.id);
        persist();
        linkingCredId = null;
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-link-cancel]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        linkingCredId = null;
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-unlink]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const id = btn.dataset.credUnlink;
        const cred = state.credentials.find(c => c.id === id);
        if (!cred) return;
        cred.finding_id = null;
        addActivity('updated_machine', `Unlinked credential "${cred.username}" from finding`, machine.id);
        persist();
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-all-edit]').forEach(el => {
      el.addEventListener('click', e => {
        if (e.target.closest('[data-cred-all-reveal],[data-cred-all-delete],[data-cred-confirm-delete],[data-cred-all-link],[data-cred-link-select],[data-cred-link-cancel],[data-cred-unlink]')) return;
        modal.close();
        openCredEditModal(el.dataset.credAllEdit);
      });
    });

    container.querySelectorAll('[data-cred-all-delete]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        pendingDeleteId = btn.dataset.credAllDelete;
        renderCredRows();
      });
    });

    container.querySelectorAll('[data-cred-confirm-delete]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const id = btn.dataset.credConfirmDelete;
        const cred = state.credentials.find(c => c.id === id);
        if (!cred) return;
        state.credentials = state.credentials.filter(c => c.id !== id);
        addActivity('updated_machine', `Deleted credential: ${cred.username}`, machine.id);
        pendingDeleteId = null;
        persist();
        renderCredRows();
      });
    });
  }

  renderCredRows();
  showDialogSafely(modal);
  modal.addEventListener('close', function onClose() {
    modal.removeEventListener('close', onClose);
    mount();
  });
  addBackdropClose(modal);
}

/** Open an inline edit modal for a single credential record. */
function openCredEditModal(credId) {
  const credential = state.credentials.find(c => c.id === credId);
  if (!credential) return;
  const modal = document.getElementById('credEditModal');
  const container = document.getElementById('credEditContent');
  if (!modal || !container) return;

  container.innerHTML = `
    <h2>Edit Credential</h2>
    <div class="split">
      <label>Username *<input id="ceUsername" value="${(credential.username || '').replace(/"/g, '&quot;')}" /></label>
      <label>Service<input id="ceService" value="${(credential.service || '').replace(/"/g, '&quot;')}" /></label>
    </div>
    <label>Password / Hash<input id="cePassword" type="text" value="${(credential.password || '').replace(/"/g, '&quot;')}" /></label>
    <label>Type
      <select id="ceType">
        ${credTypeOptionsHtml(credential.cred_type)}
      </select>
    </label>
    <div class="modal-actions">
      <button class="btn btn-ghost" id="ceCancel">Cancel</button>
      <button class="btn btn-primary" id="ceSave">Save</button>
    </div>
  `;

  container.querySelector('#ceCancel').addEventListener('click', () => modal.close());
  container.querySelector('#ceSave').addEventListener('click', () => {
    const username = document.getElementById('ceUsername').value.trim();
    if (!username) { document.getElementById('ceUsername').focus(); return; }
    credential.username = username;
    credential.service  = document.getElementById('ceService').value.trim();
    credential.password = document.getElementById('cePassword').value;
    credential.cred_type = document.getElementById('ceType').value;
    addActivity('updated_machine', `Edited credential: ${credential.username} (${credential.service || credential.cred_type})`, credential.machine_id);
    modal.close();
    mount();
  });

  showDialogSafely(modal);
  document.getElementById('ceUsername')?.select();
  addBackdropClose(modal);
}

/* ═══════════════════════════════════════════════
   Quick Finding Modal (checklist task / evidence)
   ═══════════════════════════════════════════════ */
/**
 * Quick finding creation modal triggered from the checklist.
 * Pre-fills phase based on the checklist item, and optionally
 * attaches evidence screenshots passed from the check event.
 */
function openQuickFindingModal(machine, itemId, prefillEvidence = []) {
  const item = checklistItemById(itemId);
  const phase = checklistPhaseForItem(itemId);
  const machinePhases = checklistPhaseCatalogForMachine(machine);
  const modal = document.getElementById('quickFindingModal');
  const container = document.getElementById('quickFindingContent');
  if (!modal || !container) return;

  const initPhase = phase?.id || '';

  container.innerHTML = `
    <h2 style="margin-bottom:.25rem">Create Finding</h2>
    <div class="small dim" style="margin-bottom:1rem;opacity:.7">from checklist: <em>${item?.name || itemId}</em></div>
    <label>Title *<input id="qfTitle" value="${(item?.name || '').replace(/"/g, '&quot;')}" /></label>
    <label>Description<textarea id="qfDesc" rows="24" style="width:100%;margin-top:.4rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem"></textarea></label>
    <div class="split">
      <label>Severity
        <select id="qfSev">
          ${severityOptionsHtml('info')}
        </select>
      </label>
      <label>Phase
        <select id="qfPhase">
          ${phaseOptionsHtml(machinePhases, phase?.id || '')}
        </select>
      </label>
    </div>
    <label>Parent Finding
      <select id="qfParentId">
        <option value="">Root Level (no parent)</option>
        ${parentFindingOptionsHtml(machine.id, initPhase, new Set(), null, machine)}
      </select>
    </label>
    ${prefillEvidence.length ? `
      <div style="margin-top:.6rem">
        <div class="small dim" style="margin-bottom:.3rem">Evidence attached (${prefillEvidence.length} file${prefillEvidence.length > 1 ? 's' : ''})</div>
        <div class="evidence-list">
          ${prefillEvidence.map(f => `<div class="evidence-row"><span class="small">${f.name}</span></div>`).join('')}
        </div>
      </div>
    ` : ''}
    <div class="modal-actions">
      <button class="btn btn-ghost" id="qfSkip">Skip</button>
      <button class="btn btn-primary" id="qfSave">Create Finding</button>
    </div>
  `;

  wirePhaseParentSync(container, 'qfPhase', 'qfParentId', machine.id, new Set(), null, machine);

  container.querySelector('#qfSkip').addEventListener('click', () => modal.close());
  container.querySelector('#qfSave').addEventListener('click', () => {
    const title = document.getElementById('qfTitle').value.trim();
    if (!title) { document.getElementById('qfTitle').focus(); return; }
    const finding = {
      id: uid('f'),
      machine_id: machine.id,
      title,
      description: document.getElementById('qfDesc').value,
      severity: document.getElementById('qfSev').value,
      phase: document.getElementById('qfPhase').value,
      parent_id: document.getElementById('qfParentId').value || null,
      category: 'finding',
      evidence: [...prefillEvidence],
      source_checklist_item_id: itemId,
      created_at: nowStamp(),
      updated_at: nowStamp(),
    };
    state.findings.unshift(finding);
    addActivity('added_finding', `Added finding from checklist: ${finding.title} [${finding.severity.toUpperCase()} | ${finding.phase}]${prefillEvidence.length ? ` with ${prefillEvidence.length} evidence file(s)` : ''}`, machine.id);
    modal.close();
    mount();
  });

  showDialogSafely(modal);
  document.getElementById('qfTitle')?.select();
  addBackdropClose(modal);
}

/* ═══════════════════════════════════════════════
   Finding Edit Modal (findings tab → direct edit)
   ═══════════════════════════════════════════════ */
/**
 * Direct finding edit modal — full form with title, description, severity,
 * phase, parent, evidence management, and credential linking.
 * Used from mind map node clicks and finding list edit buttons.
 */
function openFindingEditModal(findingId) {
  const finding = state.findings.find(f => f.id === findingId);
  if (!finding) return;
  const machine = machineById(finding.machine_id);
  const machinePhases = checklistPhaseCatalogForMachine(machine);
  const modal = document.getElementById('findingEditModal');
  const container = document.getElementById('findingEditContent');
  let femEvidenceBuffer = [];

  const excludeIds = new Set(getDescendantIds(finding.id, state.findings));
  const parentOptsHtml = parentFindingOptionsHtml(finding.machine_id, finding.phase, excludeIds, finding.parent_id, machine);
  const createdText = formatDateTimeMilitary(finding.created_at);
  const changedText = formatDateTimeMilitary(finding.updated_at || finding.created_at);

  const existingEvidence = finding.evidence || [];

  container.innerHTML = `
    <div class="finding-modal-header">
      <div class="finding-modal-title-row">
        <h2 style="margin:0">Edit Finding</h2>
      </div>
      <div class="finding-modal-meta">
        <div class="finding-modal-meta-row"><span>Creation:</span><strong>${createdText}</strong></div>
        <div class="finding-modal-meta-row"><span>Last Changed:</span><strong>${changedText}</strong></div>
      </div>
    </div>
    <label>Title *<input id="femTitle" value="${(finding.title || '').replace(/"/g, '&quot;')}" /></label>
    <label>Description<textarea id="femDesc" rows="24" style="width:100%;margin-top:.4rem;background:var(--bg);border:1px solid var(--line);color:var(--text);border-radius:.45rem;padding:.55rem .6rem">${(finding.description || '').replace(/</g, '&lt;')}</textarea></label>
    <div class="split">
      <label>Severity
        <select id="femSev">
          ${severityOptionsHtml(finding.severity)}
        </select>
      </label>
      <label>Phase
        <select id="femPhase">
          ${phaseOptionsHtml(machinePhases, finding.phase)}
        </select>
      </label>
    </div>
    <label>Parent Finding
      <select id="femParentId">
        <option value="">Root Level (no parent)</option>
        ${parentOptsHtml}
      </select>
    </label>
    <div class="finding-cred-box">
      <div class="small dim" style="margin-bottom:.35rem">Credentials linked to this finding</div>
      <div id="femLinkedCreds" class="finding-cred-links"></div>
      <div class="cred-action-prompt">
        <button type="button" class="btn btn-ghost" id="femShowLinkCred">Link Credential</button>
        <button type="button" class="btn btn-ghost" id="femShowCreateCred">Create New Credential</button>
      </div>
      <div id="femLinkCredSection" style="display:none">
        <label style="margin-top:.55rem">Link Existing Credential
          <select id="femLinkCredSelect"></select>
        </label>
      </div>
      <div id="femCreateCredSection" style="display:none">
        <div class="split" style="margin-top:.3rem">
          <label>Username *<input id="femNewCredUser" placeholder="admin" /></label>
          <label>Service<input id="femNewCredSvc" placeholder="SSH" /></label>
        </div>
        <div class="split" style="margin-top:.3rem">
          <label>Password / Hash<input id="femNewCredPass" /></label>
          <label>Type
            <select id="femNewCredType">
              ${credTypeOptionsHtml()}
            </select>
          </label>
        </div>
        <div style="display:flex;justify-content:flex-end;margin-top:.35rem">
          <button type="button" class="btn btn-primary" id="femCreateLinkCred">Create & Link</button>
        </div>
      </div>
    </div>
    <div style="margin-top:.6rem">
      <div class="small dim" style="margin-bottom:.3rem">Evidence</div>
      <input id="femEvidenceInput" type="file" accept="image/*" multiple style="display:none">
      <div class="evidence-dropzone" id="femEvidenceDrop" tabindex="0">Drop screenshots here or click and press Ctrl+V to paste</div>
      ${existingEvidence.length ? `
        <div class="small dim" style="margin-top:.5rem;margin-bottom:.2rem">Existing</div>
        <div class="evidence-list" id="femExistingEvidence">
          ${existingEvidence.map(file => `
            <div class="evidence-row" data-fem-existing="${file.id}">
              <button class="btn btn-ghost evidence-open" data-fem-open-evidence="${file.id}" type="button">${file.name}</button>
              <div class="evidence-actions">
                <button class="icon-btn" data-fem-rename-evidence="${file.id}" type="button" title="Rename">Rename</button>
                <button class="icon-btn" data-fem-delete-evidence="${file.id}" type="button" title="Delete">Delete</button>
              </div>
            </div>
          `).join('')}
        </div>
      ` : ''}
      <div class="evidence-list" id="femNewEvidenceList"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" id="femCancel">Cancel</button>
      <button class="btn btn-primary" id="femSave">Save</button>
    </div>
  `;

  // Track which existing evidence to remove
  const removedEvidenceIds = new Set();
  const renamedEvidenceNames = new Map();

  function renderFemBuffer() {
    const list = document.getElementById('femNewEvidenceList');
    if (!list) return;
    if (!femEvidenceBuffer.length) { list.innerHTML = ''; return; }
    list.innerHTML = '<div class="small dim" style="margin-bottom:.2rem">New</div>' + femEvidenceBuffer.map((file, i) => `
      <div class="evidence-row">
        <span class="small">${file.name}</span>
        <button class="icon-btn" data-fem-remove-buffer="${i}" type="button" title="Remove">🗑</button>
      </div>
    `).join('');
    list.querySelectorAll('[data-fem-remove-buffer]').forEach(btn => {
      btn.addEventListener('click', () => {
        femEvidenceBuffer.splice(Number(btn.dataset.femRemoveBuffer), 1);
        renderFemBuffer();
      });
    });
  }

  function addFemFiles(files) {
    const imageFiles = getImageFilesFromList(files);
    if (!imageFiles.length) return;
    femEvidenceBuffer.push(...imageFiles);
    renderFemBuffer();
  }

  function refreshFemCredentialSection() {
    const linkedHost = container.querySelector('#femLinkedCreds');
    const select = container.querySelector('#femLinkCredSelect');
    if (!linkedHost || !select) return;

    const creds = machineCredentials(finding.machine_id);
    const linked = creds.filter(c => c.finding_id === finding.id);

    linkedHost.innerHTML = linked.length
      ? linked.map(c => `
        <div class="finding-cred-row">
          <span class="mono">${(c.username || '').replace(/</g, '&lt;')}</span>
          <span class="small dim">${(c.service || c.cred_type || '').replace(/</g, '&lt;')}</span>
          <button type="button" class="icon-btn" data-fem-unlink-cred="${c.id}" title="Unlink">×</button>
        </div>
      `).join('')
      : '<div class="small dim">No linked credentials.</div>';

    const options = creds
      .filter(c => !c.finding_id || c.finding_id === finding.id)
      .map(c => `<option value="${c.id}">${c.username}${c.service ? ` (${c.service})` : ''}</option>`)
      .join('');
    select.innerHTML = '<option value="">Select credential</option>' + options;

    select.addEventListener('change', () => {
      const credId = select.value;
      if (!credId) return;
      const cred = state.credentials.find(c => c.id === credId);
      if (!cred) return;
      cred.finding_id = finding.id;
      finding.updated_at = nowStamp();
      addActivity('updated_machine', `Linked credential "${cred.username}" to finding "${finding.title}"`, finding.machine_id);
      persist();
      refreshFemCredentialSection();
    });

    linkedHost.querySelectorAll('[data-fem-unlink-cred]').forEach(btn => {
      btn.addEventListener('click', () => {
        const cred = state.credentials.find(c => c.id === btn.dataset.femUnlinkCred);
        if (!cred) return;
        cred.finding_id = null;
        finding.updated_at = nowStamp();
        addActivity('updated_machine', `Unlinked credential "${cred.username}" from finding "${finding.title}"`, finding.machine_id);
        persist();
        refreshFemCredentialSection();
      });
    });
  }

  wirePhaseParentSync(container, 'femPhase', 'femParentId', finding.machine_id, excludeIds, finding.parent_id, machineById(finding.machine_id));

  // Dropzone
  const femInput = container.querySelector('#femEvidenceInput');
  const femDrop = container.querySelector('#femEvidenceDrop');
  wireDropzone(femDrop, femInput, addFemFiles);

  // Open existing evidence
  container.querySelectorAll('[data-fem-open-evidence]').forEach(btn => {
    btn.addEventListener('click', () => openEvidencePreview(btn.dataset.femOpenEvidence));
  });

  // Delete existing evidence
  container.querySelectorAll('[data-fem-rename-evidence]').forEach(btn => {
    btn.addEventListener('click', () => {
      const evId = btn.dataset.femRenameEvidence;
      const file = (finding.evidence || []).find(entry => entry.id === evId);
      if (!file) return;
      const nextName = window.prompt('Rename evidence file', file.name || 'evidence.png');
      if (!nextName || !nextName.trim()) return;
      const cleanName = nextName.trim();
      file.name = cleanName;
      renamedEvidenceNames.set(evId, cleanName);
      const fileBtn = container.querySelector('[data-fem-open-evidence="' + evId + '"]');
      if (fileBtn) fileBtn.textContent = cleanName;
    });
  });

  container.querySelectorAll('[data-fem-delete-evidence]').forEach(btn => {
    btn.addEventListener('click', () => {
      const evId = btn.dataset.femDeleteEvidence;
      removedEvidenceIds.add(evId);
      renamedEvidenceNames.delete(evId);
      const row = container.querySelector('[data-fem-existing="' + evId + '"]');
      if (row) row.remove();
    });
  });

  container.querySelector('#femCancel').addEventListener('click', () => modal.close());

  // Credential section prompt toggles
  container.querySelector('#femShowLinkCred')?.addEventListener('click', () => {
    const linkSec = container.querySelector('#femLinkCredSection');
    const createSec = container.querySelector('#femCreateCredSection');
    const linkBtn = container.querySelector('#femShowLinkCred');
    const createBtn = container.querySelector('#femShowCreateCred');
    if (linkSec.style.display === 'none') {
      linkSec.style.display = '';
      createSec.style.display = 'none';
      linkBtn.classList.add('active');
      createBtn.classList.remove('active');
    } else {
      linkSec.style.display = 'none';
      linkBtn.classList.remove('active');
    }
  });

  container.querySelector('#femShowCreateCred')?.addEventListener('click', () => {
    const linkSec = container.querySelector('#femLinkCredSection');
    const createSec = container.querySelector('#femCreateCredSection');
    const linkBtn = container.querySelector('#femShowLinkCred');
    const createBtn = container.querySelector('#femShowCreateCred');
    if (createSec.style.display === 'none') {
      createSec.style.display = '';
      linkSec.style.display = 'none';
      createBtn.classList.add('active');
      linkBtn.classList.remove('active');
    } else {
      createSec.style.display = 'none';
      createBtn.classList.remove('active');
    }
  });

  container.querySelector('#femCreateLinkCred')?.addEventListener('click', () => {
    const username = container.querySelector('#femNewCredUser')?.value.trim();
    if (!username) { container.querySelector('#femNewCredUser')?.focus(); return; }
    const credential = {
      id: uid('c'),
      machine_id: finding.machine_id,
      username,
      password: container.querySelector('#femNewCredPass')?.value || '',
      cred_type: container.querySelector('#femNewCredType')?.value || 'plain',
      service: container.querySelector('#femNewCredSvc')?.value || '',
      finding_id: finding.id,
      created_at: nowStamp(),
    };
    state.credentials.unshift(credential);
    finding.updated_at = nowStamp();
    addActivity('added_credential', `Added credential: ${credential.username} (${credential.service || credential.cred_type})`, credential.machine_id);
    addActivity('updated_machine', `Linked credential "${credential.username}" to finding "${finding.title}"`, finding.machine_id);
    container.querySelector('#femNewCredUser').value = '';
    container.querySelector('#femNewCredPass').value = '';
    container.querySelector('#femNewCredSvc').value = '';
    container.querySelector('#femNewCredType').value = 'plain';
    persist();
    refreshFemCredentialSection();
  });

  refreshFemCredentialSection();

  container.querySelector('#femSave').addEventListener('click', async () => {
    const title = document.getElementById('femTitle').value.trim();
    if (!title) return;
    finding.title = title;
    finding.description = document.getElementById('femDesc').value;
    finding.severity = document.getElementById('femSev').value;
    finding.phase = document.getElementById('femPhase').value;
    finding.parent_id = document.getElementById('femParentId').value || null;
    finding.updated_at = nowStamp();

    for (const [evId, newName] of renamedEvidenceNames.entries()) {
      if (!removedEvidenceIds.has(evId)) {
        await updateEvidenceRecordName(evId, newName);
      }
    }

    // Remove deleted evidence from IndexedDB
    for (const evId of removedEvidenceIds) {
      await deleteEvidenceFile(evId);
    }

    // Store new evidence files
    const newEvidence = [];
    for (const file of femEvidenceBuffer) {
      const stored = await putEvidenceFile(file);
      newEvidence.push(stored);
    }

    // Merge: keep existing (minus removed) + add new
    finding.evidence = [
      ...(finding.evidence || []).filter(f => !removedEvidenceIds.has(f.id)),
      ...newEvidence,
    ];

    const totalAdded = newEvidence.length;
    const totalRemoved = removedEvidenceIds.size;
    let evidenceNote = '';
    if (totalAdded || totalRemoved) {
      const parts = [];
      if (totalAdded) parts.push('+' + totalAdded + ' evidence');
      if (totalRemoved) parts.push('-' + totalRemoved + ' evidence');
      evidenceNote = ' (' + parts.join(', ') + ')';
    }
    addActivity('updated_machine', 'Edited finding: ' + finding.title + ' [' + finding.severity.toUpperCase() + ' | ' + finding.phase + ']' + evidenceNote, finding.machine_id);
    modal.close();
    mount();
  });

  showDialogSafely(modal);
  addBackdropClose(modal);
}

/** Populate the machine <select> dropdown in the Add Credential form. */
function fillMachineSelect() {
  const select = document.getElementById('credMachineSelect');
  select.innerHTML = '<option value="">Select machine</option>' + state.machines.map((machine) => `<option value="${machine.id}">${machine.ip}${machine.hostname ? ` (${machine.hostname})` : ''}</option>`).join('');
}

/* ═══════════════════════════════════════════════
   Documentation Modal
   ═══════════════════════════════════════════════ */

/**
 * Minimal syntax highlighting for doc code blocks — colours comments to match
 * the checklist cmd-block style.  Input must already be HTML-escaped.
 */
function highlightDocCode(escapedCode) {
  return escapedCode.replace(/^(#.*)$/gm, '<span class="tok-cmt">$1</span>');
}

/**
 * Render a single documentation entry into readable HTML.
 */
function renderDocContent(doc) {
  let sectionIndex = 0;
  return doc.sections.map(s => {
    let html = '';
    if (s.heading) {
      const tag = s.level === 3 ? 'h3' : 'h2';
      const anchorId = 'doc-sec-' + sectionIndex++;
      html += `<${tag} class="doc-section-heading" id="${anchorId}">${escapeHtml(s.heading)}</${tag}>`;
    }
    if (s.content) {
      html += s.content.split('\n\n').map(p =>
        `<p class="doc-paragraph">${escapeHtml(p).replace(/\n/g, '<br>')}</p>`
      ).join('');
    }
    if (s.code) {
      html += `<div class="doc-code-wrapper">`;
      html += `<button class="doc-code-copy-btn" title="Copy to clipboard">Copy</button>`;
      html += `<div class="doc-code"><pre><code>${highlightDocCode(escapeHtml(s.code))}</code></pre></div>`;
      html += `</div>`;
    }
    if (s.list && s.list.length) {
      const tag = s.numbered ? 'ol' : 'ul';
      html += `<${tag} class="doc-list">${s.list.map(li => `<li>${escapeHtml(li)}</li>`).join('')}</${tag}>`;
    }
    return html;
  }).join('');
}

function buildDocToc(doc) {
  let idx = 0;
  return (doc.sections || [])
    .filter(s => s.heading)
    .map(s => {
      const anchorId = 'doc-sec-' + idx++;
      const indent = s.level === 3 ? ' docs-toc-sub' : '';
      return `<a href="#" class="docs-toc-link${indent}" data-target="${anchorId}">${escapeHtml(s.heading)}</a>`;
    }).join('');
}

function wireDocTocScrollSpyIn(rootEl) {
  const contentArea = rootEl.querySelector('.docs-content-body');
  const tocLinks = rootEl.querySelectorAll('.docs-toc-link');
  if (!contentArea || !tocLinks.length) return;

  tocLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = contentArea.querySelector('#' + link.dataset.target);
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  const headings = Array.from(contentArea.querySelectorAll('.doc-section-heading[id]'));
  const headingOffsets = headings.map(h => ({ id: h.id, top: h.offsetTop }));
  let activeId = '';
  let scrollRaf = null;

  function applyActive(id) {
    if (id === activeId) return;
    activeId = id;
    tocLinks.forEach((link) => {
      link.classList.toggle('active', link.dataset.target === id);
    });
  }

  function updateActiveFromScroll() {
    const top = contentArea.scrollTop + 40;
    let currentId = headingOffsets[0]?.id || '';
    for (let i = 0; i < headingOffsets.length; i++) {
      if (headingOffsets[i].top <= top) currentId = headingOffsets[i].id;
      else break;
    }
    applyActive(currentId);
    scrollRaf = null;
  }

  contentArea.addEventListener('scroll', () => {
    if (scrollRaf !== null) return;
    scrollRaf = requestAnimationFrame(updateActiveFromScroll);
  }, { passive: true });

  updateActiveFromScroll();
}

/** Simple HTML escaper for doc content. */
function escapeHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/** Wrap every occurrence of `query` inside `text` with <mark>. Both are plain strings. */
function highlightMatch(text, query) {
  if (!query) return text;
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return text.replace(new RegExp(`(${escaped})`, 'gi'), '<mark class="search-hl">$1</mark>');
}

/** Apply / clear highlights inside a DOM tree. Walks text nodes so tags stay intact. */
function applyHighlightsInEl(root, query) {
  /* Remove old marks first */
  root.querySelectorAll('mark.search-hl').forEach(m => {
    const parent = m.parentNode;
    parent.replaceChild(document.createTextNode(m.textContent), m);
    parent.normalize();
  });
  if (!query) return;
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(${escaped})`, 'gi');
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const hits = [];
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (node.parentElement && node.parentElement.closest('pre, code, .doc-code-wrapper, button, input, .docs-toc, .docs-list-nav')) continue;
    if (re.test(node.nodeValue)) hits.push(node);
    re.lastIndex = 0;
  }
  hits.forEach(node => {
    const frag = document.createDocumentFragment();
    let last = 0;
    node.nodeValue.replace(re, (match, _p1, offset) => {
      if (offset > last) frag.appendChild(document.createTextNode(node.nodeValue.slice(last, offset)));
      const mark = document.createElement('mark');
      mark.className = 'search-hl';
      mark.textContent = match;
      frag.appendChild(mark);
      last = offset + match.length;
    });
    if (last < node.nodeValue.length) frag.appendChild(document.createTextNode(node.nodeValue.slice(last)));
    node.parentNode.replaceChild(frag, node);
  });
  /* Scroll first hit into view */
  const first = root.querySelector('mark.search-hl');
  if (first) first.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/**
 * Open the Documentation modal.
 * Shows a list of all docs; clicking one shows its content.
 */
function openDocsModal(preselectedId) {
  const modal = document.getElementById('docsModal');
  const container = document.getElementById('docsModalContent');

  function renderDocsList() {
    const noteEntries = documentationEntries.map((doc, index) => ({ ...doc, navId: `docs-note-${index}` }));

    container.innerHTML = `
      <div class="docs-header">
        <h2>Documentation</h2>
        <div class="docs-header-right">
          <input type="text" class="docs-search-input" id="docsListSearch" placeholder="Search documentation…" autocomplete="off">
          <button class="btn btn-ghost docs-close-btn" id="docsCloseBtn">✕</button>
        </div>
      </div>
      <div class="docs-list-layout">
        <div class="docs-grid docs-grid-main">
          <div class="docs-card-list docs-card-list-main">
            ${noteEntries.map(doc => `
              <button class="docs-card" id="${doc.navId}" data-doc-id="${doc.id}">
                <span class="docs-card-icon">${doc.icon}</span>
                <span class="docs-card-title">${escapeHtml(doc.title)}</span>
                <span class="docs-card-arrow">→</span>
              </button>
            `).join('')}
          </div>
        </div>
        <nav class="docs-list-nav">
          <div class="docs-list-nav-title">Notes</div>
          ${noteEntries.map(doc => `
            <a href="#" class="docs-list-nav-link" data-target="${doc.navId}">${doc.icon} ${escapeHtml(doc.title)}</a>
          `).join('')}
        </nav>
      </div>
    `;

    container.querySelector('#docsCloseBtn').addEventListener('click', () => modal.close());
    const listPane = container.querySelector('.docs-grid-main');
    container.querySelectorAll('.docs-list-nav-link').forEach(link => {
      link.addEventListener('click', (event) => {
        event.preventDefault();
        const target = container.querySelector('#' + link.dataset.target);
        if (!target) return;
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        container.querySelectorAll('.docs-list-nav-link').forEach((l) => l.classList.remove('active'));
        link.classList.add('active');
      });
    });
    if (listPane && container.querySelector('.docs-list-nav-link')) {
      container.querySelector('.docs-list-nav-link').classList.add('active');
    }
    container.querySelectorAll('.docs-card').forEach(card => {
      card.addEventListener('click', () => renderDocView(card.dataset.docId));
    });

    /* Docs list search: filter cards & nav links, highlight titles */
    const docsListSearchInput = container.querySelector('#docsListSearch');
    docsListSearchInput?.addEventListener('input', () => {
      const q = (docsListSearchInput.value || '').toLowerCase().trim();
      noteEntries.forEach(doc => {
        const card = container.querySelector('#' + doc.navId);
        const navLink = container.querySelector(`.docs-list-nav-link[data-target="${doc.navId}"]`);
        if (!card) return;
        const haystack = (doc.title + ' ' + (doc.sections || []).map(s => (s.heading || '') + ' ' + (s.content || '') + ' ' + (s.code || '') + ' ' + (s.list || []).join(' ')).join(' ')).toLowerCase();
        const visible = !q || haystack.includes(q);
        card.style.display = visible ? '' : 'none';
        if (navLink) navLink.style.display = visible ? '' : 'none';
        /* Highlight title */
        const titleEl = card.querySelector('.docs-card-title');
        if (titleEl) titleEl.innerHTML = q ? highlightMatch(escapeHtml(doc.title), q) : escapeHtml(doc.title);
      });
    });
  }

  function renderDocView(docId) {
    const doc = documentationEntries.find(d => d.id === docId);
    if (!doc) return;

    container.innerHTML = `
      <div class="docs-header">
        <div class="docs-header-left">
          <button class="btn btn-ghost docs-back-btn" id="docsBackBtn">← Back</button>
          <h2>${doc.icon} ${doc.title}</h2>
        </div>
        <div class="docs-header-right">
          <input type="text" class="docs-search-input" id="docsContentSearch" placeholder="Search in this page…" autocomplete="off">
          <button class="btn btn-ghost docs-close-btn" id="docsCloseBtn">✕</button>
        </div>
      </div>
      <div class="docs-view-layout">
        <div class="docs-content-body">
          ${renderDocContent(doc)}
        </div>
        <nav class="docs-toc">
          <div class="docs-toc-title">On this page</div>
          ${buildDocToc(doc)}
        </nav>
      </div>
    `;

    container.querySelector('#docsCloseBtn').addEventListener('click', () => modal.close());
    container.querySelector('#docsBackBtn').addEventListener('click', () => renderDocsList());
    wireDocTocScrollSpyIn(container);
    wireDocCodeCopyButtons(container);

    /* In-page search with highlighting */
    const contentSearch = container.querySelector('#docsContentSearch');
    const contentBody = container.querySelector('.docs-content-body');
    let searchDebounce = null;
    contentSearch?.addEventListener('input', () => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        const q = (contentSearch.value || '').trim();
        applyHighlightsInEl(contentBody, q);
      }, 200);
    });
  }

  if (preselectedId) {
    renderDocView(preselectedId);
  } else {
    renderDocsList();
  }

  showDialogSafely(modal);
}

/* ═══════════════════════════════════════════════
   Checklist Modal
   ═══════════════════════════════════════════════ */
/**
 * Open the checklist as a full-screen modal.
 * Renders the same checklist accordion but inside a <dialog>.
 */
function openChecklistModal(machine) {
  const modal = document.getElementById('checklistModal');
  const container = document.getElementById('checklistModalContent');
  if (!modal || !container) return;

  function renderChecklistModalContent() {
    const checklistNavPhases = checklistPhasesFor(machine);
    const checklistHtml = renderChecklist(machine);

    container.innerHTML = `
      <div class="docs-header">
        <h2>📋 Checklist — ${machine.ip}</h2>
        <div class="docs-header-right">
          <button class="btn btn-ghost docs-close-btn" id="checklistCloseBtn">✕</button>
        </div>
      </div>
      <div class="checklist-modal-layout">
        <div class="checklist-modal-main">
          ${checklistHtml}
        </div>
        <div class="checklist-modal-toc">
          <div class="small dim" style="margin-bottom:.6rem">Sections</div>
          <input type="text" class="section-toc-search" id="tocSearchInput" placeholder="Search tasks…" autocomplete="off" style="margin-bottom:.6rem">
          <div class="section-toc-list">
            ${checklistNavPhases.map((phase) => {
              const expanded = state.ui.openPhases.includes(phase.id);
              const completedSet = new Set(machine.completed_items || []);
              return `
                <div class="section-toc-group">
                  <button class="section-toc-link${expanded ? ' expanded' : ''}" data-phase-toggle="${phase.id}" type="button" style="color:${phaseColor(phase.id)}">${phase.name} <span class="chevron">${expanded ? '▼' : '▶'}</span></button>
                  <div class="section-toc-sublist" style="display:${expanded ? 'block' : 'none'}">
                    ${phase.items.map((item) => `
                      <button class="section-toc-task${completedSet.has(item.id) ? ' completed' : ''}" data-task-jump="${item.id}" data-task-phase="${phase.id}" data-task-link="${item.id}" type="button">${item.name}</button>
                    `).join('')}
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>
      </div>
    `;

    container.querySelector('#checklistCloseBtn').addEventListener('click', () => modal.close());
    wireChecklistInModal(machine, container, renderChecklistModalContent);
  }

  renderChecklistModalContent();
  showDialogSafely(modal);
  addBackdropClose(modal);
}

/**
 * Wire checklist event listeners inside the checklist modal.
 * Similar to wireChecklist but scoped to the modal container,
 * and re-renders within the modal instead of calling mount().
 */
function wireChecklistInModal(machine, container, rerenderFn) {
  const machinePhases = checklistPhaseCatalogForMachine(machine);

  async function addChecklistEvidence(itemId, files) {
    const imageFiles = getImageFilesFromList(files);
    if (!imageFiles.length) return;
    const checklistItem = checklistItemById(itemId);
    machine.item_evidence = machine.item_evidence || {};
    machine.item_evidence[itemId] = machine.item_evidence[itemId] || [];
    for (const file of imageFiles) {
      const stored = await putEvidenceFile(file);
      machine.item_evidence[itemId].push(stored);
    }
    addActivity('updated_checklist', `Added ${imageFiles.length} evidence file(s) to checklist item: ${checklistItem?.name || itemId}`, machine.id);
    rerenderFn();
  }

  container.querySelector('#resetChecklistBtn')?.addEventListener('click', async () => {
    const confirmed = window.confirm('Reset checklist progress and checklist evidence for this machine?');
    if (!confirmed) return;
    const allEvidence = Object.values(machine.item_evidence || {}).flat();
    const completedCount = (machine.completed_items || []).length;
    await Promise.all(allEvidence.map((file) => deleteEvidenceFile(file.id)));
    machine.completed_items = [];
    machine.item_notes = {};
    machine.item_evidence = {};
    addActivity('updated_checklist', `Reset checklist: cleared ${completedCount} completed item(s) and ${allEvidence.length} evidence file(s)`, machine.id);
    rerenderFn();
  });

  container.querySelector('#showCompletedTasksBtn')?.addEventListener('click', () => {
    state.ui.checklistTaskFilter = state.ui.checklistTaskFilter === 'completed' ? 'all' : 'completed';
    rerenderFn();
  });

  container.querySelector('#showIncompleteTasksBtn')?.addEventListener('click', () => {
    state.ui.checklistTaskFilter = state.ui.checklistTaskFilter === 'incomplete' ? 'all' : 'incomplete';
    rerenderFn();
  });

  /* ── Section TOC search ── */
  let tocSearchTimer;
  const tocSearchInput = container.querySelector('#tocSearchInput');
  tocSearchInput?.addEventListener('input', () => {
    clearTimeout(tocSearchTimer);
    tocSearchTimer = setTimeout(() => {
      const q = (tocSearchInput.value || '').toLowerCase().trim();
      container.querySelectorAll('.section-toc-task').forEach(btn => {
        const itemIds = (btn.dataset.taskGroup || btn.dataset.taskLink || '').split(',').map(id => id.trim()).filter(Boolean);
        const item0 = itemIds.length ? checklistItemById(itemIds[0]) : null;
        if (item0) btn.innerHTML = q ? highlightMatch(escapeHtml(item0.name), q) : escapeHtml(item0.name);
        if (!q) { btn.style.display = ''; return; }
        const searchItems = itemIds.map((id) => checklistItemById(id)).filter(Boolean);
        if (!searchItems.length) { btn.style.display = 'none'; return; }
        const haystack = searchItems.map((item) => [item.name || '', item.description || '', item.command || '', ...(item.commands || []).flatMap(c => [c.desc || '', ...(c.entries || []).map(e => (e.cmd || '') + ' ' + (e.subdesc || ''))])].join(' ')).join(' ').toLowerCase();
        btn.style.display = haystack.includes(q) ? '' : 'none';
      });
      container.querySelectorAll('.section-toc-group').forEach(group => {
        const sublist = group.querySelector('.section-toc-sublist');
        if (!sublist) return;
        const anyVisible = [...sublist.querySelectorAll('.section-toc-task')].some(b => b.style.display !== 'none');
        group.style.display = anyVisible || !q ? '' : 'none';
        if (q && anyVisible) sublist.style.display = 'block';
      });
      container.querySelectorAll('.check-item').forEach(el => {
        if (!q) { el.style.display = ''; el.querySelectorAll('mark.search-hl').forEach(m => { const p = m.parentNode; p.replaceChild(document.createTextNode(m.textContent), m); p.normalize(); }); return; }
        const text = el.textContent.toLowerCase();
        const visible = text.includes(q);
        el.style.display = visible ? '' : 'none';
        if (visible) applyHighlightsInEl(el, q);
      });
      container.querySelectorAll('.accordion-item').forEach(acc => {
        if (!q) { acc.style.display = ''; return; }
        const anyVisible = [...acc.querySelectorAll('.check-item')].some(el => el.style.display !== 'none');
        acc.style.display = anyVisible ? '' : 'none';
        if (anyVisible) { const body = acc.querySelector('.accordion-body'); if (body) body.style.display = 'block'; }
      });
    }, 150);
  });

  container.querySelectorAll('[data-phase-toggle]').forEach((button) => {
    button.addEventListener('click', () => {
      const id = button.dataset.phaseToggle;
      const open = state.ui.openPhases.includes(id);
      if (open) state.ui.openPhases = state.ui.openPhases.filter((phaseId) => phaseId !== id);
      else state.ui.openPhases.push(id);
      rerenderFn();
    });
  });

  container.querySelectorAll('[data-phase-jump]').forEach((button) => {
    button.addEventListener('click', () => {
      const phaseId = button.dataset.phaseJump;
      if (!state.ui.openPhases.includes(phaseId)) {
        state.ui.openPhases.push(phaseId);
        rerenderFn();
      }
      requestAnimationFrame(() => {
        container.querySelector(`#phase-${machine.id}-${phaseId}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });
  });

  container.querySelectorAll('[data-task-jump]').forEach((button) => {
    button.addEventListener('click', () => {
      const taskId = button.dataset.taskJump;
      const phaseId = button.dataset.taskPhase;
      if (!taskId || !phaseId) return;
      if (!state.ui.openPhases.includes(phaseId)) {
        state.ui.openPhases.push(phaseId);
        rerenderFn();
      }
      requestAnimationFrame(() => {
        container.querySelector(`#task-${machine.id}-${taskId}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });
  });

  container.querySelectorAll('[data-check-item]').forEach((checkbox) => {
    checkbox.addEventListener('change', () => {
      const itemId = checkbox.dataset.checkItem;
      const checklistItem = checklistItemById(itemId);
      const set = new Set(machine.completed_items || []);
      const justCompleted = checkbox.checked;

      if (!justCompleted) {
        const linkedFindings = state.findings.filter(f => f.source_checklist_item_id === itemId);
        if (linkedFindings.length) {
          const names = linkedFindings.map(f => `  • ${f.title} [${f.severity.toUpperCase()}]`).join('\n');
          const ok = confirm(`This checklist item has ${linkedFindings.length} linked finding(s):\n\n${names}\n\nUnchecking will DELETE these findings.\n\nContinue?`);
          if (!ok) { checkbox.checked = true; return; }
          for (const lf of linkedFindings) archiveFindingData(machine, lf, 'finding_deleted_via_uncheck');
          state.findings = state.findings.filter(f => f.source_checklist_item_id !== itemId);
        }
      }

      if (set.has(itemId)) set.delete(itemId);
      else set.add(itemId);
      machine.completed_items = Array.from(set);
      addActivity('updated_checklist', `${justCompleted ? 'Completed' : 'Unchecked'} checklist item: ${checklistItem?.name || itemId}`, machine.id);
      persist();
      rerenderFn();
    });
  });

  container.querySelectorAll('[data-copy-cmd],[data-copy-raw-idx]').forEach((button) => {
    button.addEventListener('click', async () => {
      let text;
      if (button.dataset.copyRawIdx !== undefined) {
        const parts = button.dataset.copyRawIdx.split('__');
        const itemId = parts[0];
        const ci = parseInt(parts[1], 10);
        const ei = parseInt(parts[2], 10);
        const item = machinePhases.flatMap((phase) => phase.items).find((entry) => entry.id === itemId);
        if (!item || !item.commands) return;
        text = substituteTargetIp(item.commands[ci].entries[ei].cmd, machine.ip);
      } else {
        const item = machinePhases.flatMap((phase) => phase.items).find((entry) => entry.id === button.dataset.copyCmd);
        if (!item) return;
        text = substituteTargetIp(item.command, machine.ip);
      }
      await navigator.clipboard.writeText(text);
      showCopyFeedback(button, 'Copied!');
    });
  });

  container.querySelectorAll('[data-evidence-upload]').forEach((input) => {
    input.addEventListener('change', async () => {
      const itemId = input.dataset.evidenceUpload;
      await addChecklistEvidence(itemId, input.files || []);
      input.value = '';
    });
  });

  container.querySelectorAll('[data-evidence-drop]').forEach((dz) => {
    dz.addEventListener('click', () => {
      const input = container.querySelector(`[data-evidence-upload="${dz.dataset.evidenceDrop}"]`);
      if (input) input.click();
    });
    dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('dragover'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
    dz.addEventListener('drop', async (e) => {
      e.preventDefault();
      dz.classList.remove('dragover');
      await addChecklistEvidence(dz.dataset.evidenceDrop, e.dataTransfer.files);
    });
    dz.addEventListener('focus', () => dz.classList.add('focused'));
    dz.addEventListener('blur', () => dz.classList.remove('focused'));
    dz.addEventListener('keydown', (e) => {
      if (e.key === 'v' && (e.ctrlKey || e.metaKey)) {
        /* handled by paste below */
      }
    });
    dz.addEventListener('paste', async (e) => {
      const items = e.clipboardData?.items;
      if (!items) return;
      const files = [];
      for (const item of items) {
        if (item.type.startsWith('image/')) {
          const f = item.getAsFile();
          if (f) files.push(f);
        }
      }
      if (files.length) {
        e.preventDefault();
        await addChecklistEvidence(dz.dataset.evidenceDrop, files);
      }
    });
  });

  container.querySelectorAll('[data-open-evidence]').forEach((btn) => {
    btn.addEventListener('click', () => openEvidencePreview(btn.dataset.openEvidence));
  });

  container.querySelectorAll('[data-delete-evidence]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const fileId = btn.dataset.deleteEvidence;
      const itemId = btn.dataset.itemId;
      const ok = confirm('Delete this evidence file?');
      if (!ok) return;
      await deleteEvidenceFile(fileId);
      if (machine.item_evidence?.[itemId]) {
        machine.item_evidence[itemId] = machine.item_evidence[itemId].filter(f => f.id !== fileId);
      }
      persist();
      rerenderFn();
    });
  });

  container.querySelectorAll('[data-rename-evidence]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const fileId = btn.dataset.renameEvidence;
      const itemId = btn.dataset.itemId;
      const file = (machine.item_evidence?.[itemId] || []).find(f => f.id === fileId);
      if (!file) return;
      const newName = prompt('Rename evidence file:', file.name);
      if (!newName || newName === file.name) return;
      file.name = newName;
      await updateEvidenceRecordName(fileId, newName);
      persist();
      rerenderFn();
    });
  });
}

/** Wire click handlers for .doc-code-copy-btn buttons inside a root element. */
function wireDocCodeCopyButtons(rootEl) {
  rootEl.querySelectorAll('.doc-code-copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const codeEl = btn.closest('.doc-code-wrapper')?.querySelector('code');
      if (!codeEl) return;
      try {
        await navigator.clipboard.writeText(codeEl.textContent);
        const original = btn.textContent;
        btn.textContent = '✅ Copied!';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 2000);
      } catch { /* clipboard blocked */ }
    });
  });
}

/**
 * Open the AI Penetration Testing modal.
 * Shows a list of AI pentesting notes; clicking one shows its content.
 */
function openAiDocsModal(preselectedId) {
  const modal = document.getElementById('aiDocsModal');
  const container = document.getElementById('aiDocsModalContent');
  const entries = Array.isArray(aiDocumentationEntries) ? aiDocumentationEntries : [];

  function renderDocsList() {
    const noteEntries = entries.map((doc, index) => ({ ...doc, navId: `ai-docs-note-${index}` }));

    container.innerHTML = `
      <div class="docs-header">
        <h2>AI Penetration Testing</h2>
        <div class="docs-header-right">
          <input type="text" class="docs-search-input" id="aiDocsListSearch" placeholder="Search AI docs…" autocomplete="off">
          <button class="btn btn-ghost docs-close-btn" id="aiDocsCloseBtn">✕</button>
        </div>
      </div>
      <div class="docs-list-layout">
        <div class="docs-grid docs-grid-main">
          <div class="docs-card-list docs-card-list-main">
            ${noteEntries.map(doc => `
              <button class="docs-card" id="${doc.navId}" data-doc-id="${doc.id}">
                <span class="docs-card-icon">${doc.icon}</span>
                <span class="docs-card-title">${escapeHtml(doc.title)}</span>
                <span class="docs-card-arrow">→</span>
              </button>
            `).join('')}
          </div>
        </div>
        <nav class="docs-list-nav">
          <div class="docs-list-nav-title">Notes</div>
          ${noteEntries.map(doc => `
            <a href="#" class="docs-list-nav-link" data-target="${doc.navId}">${doc.icon} ${escapeHtml(doc.title)}</a>
          `).join('')}
        </nav>
      </div>
    `;

    container.querySelector('#aiDocsCloseBtn').addEventListener('click', () => modal.close());
    const listPane = container.querySelector('.docs-grid-main');
    container.querySelectorAll('.docs-list-nav-link').forEach(link => {
      link.addEventListener('click', (event) => {
        event.preventDefault();
        const target = container.querySelector('#' + link.dataset.target);
        if (!target) return;
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        container.querySelectorAll('.docs-list-nav-link').forEach((l) => l.classList.remove('active'));
        link.classList.add('active');
      });
    });
    if (listPane && container.querySelector('.docs-list-nav-link')) {
      container.querySelector('.docs-list-nav-link').classList.add('active');
    }
    container.querySelectorAll('.docs-card').forEach(card => {
      card.addEventListener('click', () => renderDocView(card.dataset.docId));
    });

    /* AI Docs list search: filter cards & nav links, highlight titles */
    const aiDocsListSearch = container.querySelector('#aiDocsListSearch');
    aiDocsListSearch?.addEventListener('input', () => {
      const q = (aiDocsListSearch.value || '').toLowerCase().trim();
      noteEntries.forEach(doc => {
        const card = container.querySelector('#' + doc.navId);
        const navLink = container.querySelector(`.docs-list-nav-link[data-target="${doc.navId}"]`);
        if (!card) return;
        const haystack = (doc.title + ' ' + (doc.sections || []).map(s => (s.heading || '') + ' ' + (s.content || '') + ' ' + (s.code || '') + ' ' + (s.list || []).join(' ')).join(' ')).toLowerCase();
        const visible = !q || haystack.includes(q);
        card.style.display = visible ? '' : 'none';
        if (navLink) navLink.style.display = visible ? '' : 'none';
        const titleEl = card.querySelector('.docs-card-title');
        if (titleEl) titleEl.innerHTML = q ? highlightMatch(escapeHtml(doc.title), q) : escapeHtml(doc.title);
      });
    });
  }

  function renderDocView(docId) {
    const doc = entries.find(d => d.id === docId);
    if (!doc) return;

    container.innerHTML = `
      <div class="docs-header">
        <div class="docs-header-left">
          <button class="btn btn-ghost docs-back-btn" id="aiDocsBackBtn">← Back</button>
          <h2>${doc.icon} ${doc.title}</h2>
        </div>
        <div class="docs-header-right">
          <input type="text" class="docs-search-input" id="aiDocsContentSearch" placeholder="Search in this page…" autocomplete="off">
          <button class="btn btn-ghost docs-close-btn" id="aiDocsCloseBtn">✕</button>
        </div>
      </div>
      <div class="docs-view-layout">
        <div class="docs-content-body">
          ${renderDocContent(doc)}
        </div>
        <nav class="docs-toc">
          <div class="docs-toc-title">On this page</div>
          ${buildDocToc(doc)}
        </nav>
      </div>
    `;

    container.querySelector('#aiDocsCloseBtn').addEventListener('click', () => modal.close());
    container.querySelector('#aiDocsBackBtn').addEventListener('click', () => renderDocsList());
    wireDocTocScrollSpyIn(container);
    wireDocCodeCopyButtons(container);

    /* In-page search with highlighting */
    const contentSearch = container.querySelector('#aiDocsContentSearch');
    const contentBody = container.querySelector('.docs-content-body');
    let searchDebounce = null;
    contentSearch?.addEventListener('input', () => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        const q = (contentSearch.value || '').trim();
        applyHighlightsInEl(contentBody, q);
      }, 200);
    });
  }

  if (preselectedId) {
    renderDocView(preselectedId);
  } else {
    renderDocsList();
  }

  showDialogSafely(modal);
}

/* ───────────────────────────────────────────────
  27. Global Event Listeners & Initial Mount
   ─────────────────────────────────────────────── */

/* Re-render the page whenever the URL hash changes. */
window.addEventListener('hashchange', mount);

/* ── Image zoom modal ── */
{
  const zoomModal = document.getElementById('imageZoomModal');
  const zoomClose = document.getElementById('imageZoomClose');
  if (zoomModal) {
    zoomClose?.addEventListener('click', () => zoomModal.close());
    zoomModal.addEventListener('click', (e) => {
      /* Close if clicking the backdrop (outside the image) */
      if (e.target === zoomModal) zoomModal.close();
    });
  }
}

/* Sidebar collapse/expand toggle. */
document.getElementById('sidebarToggle').addEventListener('click', () => {
  state.ui.sidebarCollapsed = !state.ui.sidebarCollapsed;
  sidebar.classList.toggle('collapsed', state.ui.sidebarCollapsed);
  brand.style.display = state.ui.sidebarCollapsed ? 'none' : 'block';
  document.getElementById('sidebarToggle').textContent = state.ui.sidebarCollapsed ? '▶' : '◀';
  persist();
});

/* Cancel buttons on the static Add Machine / Add Credential modals. */
document.getElementById('cancelMachine').addEventListener('click', () => {
  document.getElementById('machineModal').close();
});

document.getElementById('cancelCred').addEventListener('click', () => {
  document.getElementById('credModal').close();
});

/* Submit handler: create a new machine and re-mount. */
document.getElementById('machineForm').addEventListener('submit', (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const machine = {
    id: uid('m'),
    ip: String(form.get('ip') || '').trim(),
    hostname: String(form.get('hostname') || '').trim(),
    os_type: String(form.get('os_type') || 'linux'),
    tags: String(form.get('tags') || '').split(',').map((item) => item.trim()).filter(Boolean),
    osint_enabled: true,
    persistence_enabled: true,
    status: 'pending',
    created_at: nowStamp(),
    notes: '',
    selected_ports: [],
    completed_items: [],
    item_notes: {},
    item_evidence: {},
  };

  if (!machine.ip) return;

  state.machines.unshift(machine);
  addActivity('added_machine', `Added machine ${machine.ip} (${machine.os_type})`, machine.id);
  document.getElementById('machineModal').close();
  event.target.reset();
  mount();
});

/* Submit handler: create a new credential and re-mount. */
document.getElementById('credForm').addEventListener('submit', (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const credential = {
    id: uid('c'),
    machine_id: String(form.get('machine_id') || ''),
    username: String(form.get('username') || '').trim(),
    password: String(form.get('password') || ''),
    cred_type: String(form.get('cred_type') || 'plain'),
    service: String(form.get('service') || ''),
    created_at: nowStamp(),
  };

  if (!credential.machine_id || !credential.username) return;

  state.credentials.unshift(credential);
  addActivity('added_credential', `Added credential: ${credential.username} (${credential.service || credential.cred_type})`, credential.machine_id);
  document.getElementById('credModal').close();
  event.target.reset();
  mount();
});

/* Restore collapsed sidebar state from persisted UI prefs. */
if (state.ui.sidebarCollapsed) {
  sidebar.classList.add('collapsed');
  brand.style.display = 'none';
  document.getElementById('sidebarToggle').textContent = '▶';
}

/* Ensure a default hash route exists, request persistent storage, and boot. */
if (!window.location.hash) window.location.hash = '#/';
requestPersistentStorage();
mount();
