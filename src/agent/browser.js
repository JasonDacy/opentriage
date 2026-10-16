// Chrome adapter used by the agent tools. Kept separate so the agent and
// tools can be tested in Node with a fake browser.
//
// Everything here is scoped to the session tab group (see session-tabs.js):
// the agent can only list, read and act on tabs the analyst put in the group,
// and tabs it opens are added to the group.

import {
  snapshotFrame,
  describeElement,
  clickElement,
  typeIntoElement,
  scrollFrame,
  viewportInfo,
  elementAtPoint,
  clickAtPoint,
  focusedElement,
  pressKey,
  elementCenter,
  focusRef,
} from '../content/page-functions.js';
import { createTabSession } from './session-tabs.js';
import { createTrustedInput, trustedInputAvailable } from './trusted-input.js';

const MAX_SHOT_WIDTH = 1280;
const MAX_SHOT_HEIGHT = 1600;

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return '';
  }
}

export function parseRef(fullRef) {
  const m = String(fullRef).match(/^(\d+):(\w+)$/);
  if (!m) return null;
  return { frameId: Number(m[1]), ref: m[2] };
}

function waitForLoad(tabId, timeoutMs = 20000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      chrome.tabs.onUpdated.removeListener(listener);
      // SPA consoles keep rendering after "complete"; give them a moment.
      setTimeout(resolve, 1500);
    };
    const listener = (id, info) => {
      if (id === tabId && info.status === 'complete') finish();
    };
    chrome.tabs.onUpdated.addListener(listener);
    setTimeout(finish, timeoutMs);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Downscale a captured data URL so screenshots stay cheap and predictable. */
async function shrink(dataUrl) {
  const blob = await (await fetch(dataUrl)).blob();
  const bmp = await createImageBitmap(blob);
  const scale = Math.min(1, MAX_SHOT_WIDTH / bmp.width, MAX_SHOT_HEIGHT / bmp.height);
  const w = Math.round(bmp.width * scale);
  const h = Math.round(bmp.height * scale);
  const canvas = new OffscreenCanvas(w, h);
  canvas.getContext('2d').drawImage(bmp, 0, 0, w, h);
  const out = await canvas.convertToBlob({ type: 'image/jpeg', quality: 0.75 });
  const buf = new Uint8Array(await out.arrayBuffer());
  let bin = '';
  for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  return { data: btoa(bin), mediaType: 'image/jpeg', width: w, height: h };
}

/**
 * @param {object} [opts]
 * @param {number} [opts.pinnedTabId] Treat this tab as "the analyst's current tab"
 *   instead of the focused one (used when the panel is opened as a page, e.g. in tests).
 */
export function chromeBrowser({ pinnedTabId = null, popout = false, inputMode = () => 'simulated' } = {}) {
  const tabSession = createTabSession(chrome);
  let lastCapture = 0;
  const trusted = trustedInputAvailable() ? createTrustedInput() : null;
  const useTrusted = () => !!trusted && inputMode() === 'trusted';

  /** Main-frame viewport position of an element ref, or null if trusted input can't target it. */
  async function trustedPoint(tabId, p) {
    const c = await run(tabId, p.frameId, elementCenter, [p.ref]);
    if (!c) return { error: `No element ${p.frameId}:${p.ref}. Take a new snapshot.` };
    if (p.frameId === 0) return c;
    const frames = (await chrome.webNavigation.getAllFrames({ tabId })) || [];
    const f = frames.find((x) => x.frameId === p.frameId);
    if (!f || f.parentFrameId !== 0) return null; // nested frames: fall back to simulated input
    const off = await trusted.frameOffset(tabId, f.url).catch(() => null);
    return off ? { x: c.x + off.x, y: c.y + off.y } : null;
  }

  async function run(tabId, frameId, func, args = []) {
    const [res] = await chrome.scripting.executeScript({ target: { tabId, frameIds: [frameId] }, func, args });
    return res ? res.result : null;
  }

  return {
    session: tabSession,

    /** The tab the analyst is looking at (may or may not be in the session). */
    async activeTab() {
      if (pinnedTabId) {
        try {
          const t = await chrome.tabs.get(pinnedTabId);
          return { id: t.id, url: t.url || '', title: t.title || '' };
        } catch {
          return null;
        }
      }
      if (popout) {
        // In a pop-out window "current tab" means the active tab of the last-focused browser window.
        try {
          const win = await chrome.windows.getLastFocused({ windowTypes: ['normal'] });
          const [t] = await chrome.tabs.query({ active: true, windowId: win.id });
          return t ? { id: t.id, url: t.url || '', title: t.title || '' } : null;
        } catch {
          return null;
        }
      }
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      return tab ? { id: tab.id, url: tab.url || '', title: tab.title || '' } : null;
    },

    /** Session tabs only. */
    async listTabs() {
      return tabSession.list();
    },

    async inSession(tabId) {
      return tabSession.has(tabId);
    },

    async addToSession(tabId) {
      return tabSession.add(tabId);
    },

    /** Chrome only lets extensions capture tabs with the all-sites permission (trusted input captures through the debugger instead). */
    async canScreenshot() {
      return useTrusted() || chrome.permissions.contains({ origins: ['<all_urls>'] });
    },

    inputMode() {
      return useTrusted() ? 'trusted' : 'simulated';
    },

    /** End-of-turn cleanup: detach the debugger so Chrome's banner goes away. */
    async release() {
      await trusted?.releaseAll();
    },

    async hasAccess(url) {
      const origin = originOf(url);
      if (!origin.startsWith('https://')) return false;
      return chrome.permissions.contains({ origins: [origin + '/*'] });
    },

    async snapshot(tabId, opts = {}) {
      const tab = await chrome.tabs.get(tabId);
      const frames = (await chrome.webNavigation.getAllFrames({ tabId })) || [{ frameId: 0, url: tab.url }];
      const results = [];
      const blocked = new Set();
      for (const f of frames.slice(0, 40)) {
        if (!/^https:/.test(f.url)) continue;
        try {
          const r = await run(tabId, f.frameId, snapshotFrame, [opts]);
          if (r && (r.text.trim() || r.elements.length)) results.push({ frameId: f.frameId, ...r });
        } catch {
          blocked.add(originOf(f.url));
        }
      }
      return { tabId, url: tab.url, title: tab.title, frames: results, blockedOrigins: [...blocked].filter(Boolean) };
    },

    /**
     * Screenshot of a session tab's visible area. Chrome can only capture the
     * active tab of a window, so a background tab is brought forward briefly
     * and the analyst's previous tab is restored afterwards.
     */
    async screenshot(tabId) {
      if (useTrusted()) {
        const dataUrl = await trusted.screenshot(tabId);
        const vp = await run(tabId, 0, viewportInfo);
        return { ...(await shrink(dataUrl)), viewport: vp };
      }
      const tab = await chrome.tabs.get(tabId);
      let restore = null;
      if (!tab.active) {
        const [prev] = await chrome.tabs.query({ active: true, windowId: tab.windowId });
        restore = prev?.id ?? null;
        await chrome.tabs.update(tabId, { active: true });
        await sleep(400);
      }
      try {
        const wait = 550 - (Date.now() - lastCapture); // Chrome allows ~2 captures per second
        if (wait > 0) await sleep(wait);
        const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'jpeg', quality: 80 });
        lastCapture = Date.now();
        const vp = await run(tabId, 0, viewportInfo);
        const img = await shrink(dataUrl);
        return { ...img, viewport: vp };
      } finally {
        if (restore !== null && restore !== tabId) await chrome.tabs.update(restore, { active: true }).catch(() => {});
      }
    },

    /** Run a self-contained function in a tab's top frame (used for same-origin API calls such as Confluence). */
    async runInTab(tabId, func, args = []) {
      return run(tabId, 0, func, args);
    },

    async describe(tabId, fullRef) {
      const p = parseRef(fullRef);
      if (!p) return null;
      return run(tabId, p.frameId, describeElement, [p.ref]);
    },

    async describeAt(tabId, x, y) {
      return run(tabId, 0, elementAtPoint, [x, y]);
    },

    async describeFocus(tabId, fullRef) {
      const p = fullRef ? parseRef(fullRef) : { frameId: 0, ref: null };
      if (!p) return null;
      return run(tabId, p.frameId, focusedElement, [p.ref]);
    },

    async click(tabId, fullRef) {
      const p = parseRef(fullRef);
      if (!p) return { ok: false, error: 'Bad ref. Use the frame:ref form shown in the snapshot, e.g. 0:12' };
      if (useTrusted()) {
        const pt = await trustedPoint(tabId, p);
        if (pt?.error) return { ok: false, error: pt.error };
        if (pt) {
          await trusted.mouseClick(tabId, pt.x, pt.y);
          await sleep(1200);
          return { ok: true, trusted: true };
        }
      }
      const r = await run(tabId, p.frameId, clickElement, [p.ref]);
      await sleep(1200);
      return r;
    },

    async clickAt(tabId, x, y) {
      if (useTrusted()) {
        await trusted.mouseClick(tabId, x, y);
        await sleep(1200);
        return { ok: true, trusted: true };
      }
      const r = await run(tabId, 0, clickAtPoint, [x, y]);
      await sleep(1200);
      return r;
    },

    async pressKey(tabId, key, fullRef) {
      const p = fullRef ? parseRef(fullRef) : { frameId: 0, ref: null };
      if (!p) return { ok: false, error: 'Bad ref. Use the frame:ref form, e.g. 0:12' };
      if (useTrusted()) {
        if (p.ref) {
          const f = await run(tabId, p.frameId, focusRef, [p.ref]);
          if (!f.ok) return f;
        }
        await trusted.key(tabId, key);
        await sleep(600);
        return { ok: true, trusted: true };
      }
      const r = await run(tabId, p.frameId, pressKey, [key, p.ref]);
      await sleep(600);
      return r;
    },

    async type(tabId, fullRef, text, submit) {
      const p = parseRef(fullRef);
      if (!p) return { ok: false, error: 'Bad ref. Use the frame:ref form, e.g. 0:12' };
      if (useTrusted()) {
        const f = await run(tabId, p.frameId, focusRef, [p.ref]);
        if (!f.ok) return f;
        await trusted.selectAll(tabId);
        await trusted.insertText(tabId, text);
        if (submit) {
          await trusted.key(tabId, 'Enter');
          await sleep(1500);
        }
        return { ok: true, trusted: true };
      }
      const r = await run(tabId, p.frameId, typeIntoElement, [p.ref, text, !!submit]);
      if (submit) await sleep(1500);
      return r;
    },

    async scroll(tabId, direction, fullRef) {
      const p = fullRef ? parseRef(fullRef) : { frameId: 0, ref: null };
      return run(tabId, p ? p.frameId : 0, scrollFrame, [direction, p ? p.ref : null]);
    },

    async navigate(tabId, url) {
      await chrome.tabs.update(tabId, { url });
      await waitForLoad(tabId);
      return { ok: true };
    },

    /** Open a background tab and add it to the session group. */
    async openTab(url) {
      const tab = await chrome.tabs.create({ url, active: false });
      await tabSession.add(tab.id);
      await waitForLoad(tab.id);
      return { ok: true, tabId: tab.id };
    },

    async switchTo(tabId) {
      await chrome.tabs.update(tabId, { active: true });
      return { ok: true };
    },
  };
}
