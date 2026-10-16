// OpenTriage background service worker.
//
// The agent itself runs inside the side panel page, not here: MV3 service
// workers can be suspended while the agent waits on an analyst approval, and
// an extension page has the same chrome.* APIs without that lifetime problem.
// This worker only wires up the toolbar button and the context menus.

import { createTabSession } from '../agent/session-tabs.js';
import { chromeStorage } from '../lib/storage.js';
import { createAudit } from '../lib/audit.js';
import { createMemory } from '../memory/memory.js';

const tabSession = createTabSession(chrome);

// Team builds (npm run package -- --env <file>) carry the team's environment
// facts at src/team/environment.json. Standard builds don't have the file.
const TEAM_VERSION_KEY = 'ot.teamEnvVersion';
async function syncTeamEnvironment() {
  if (!/team build/i.test(chrome.runtime.getManifest().version_name || '')) return; // standard build
  let bundle;
  try {
    const res = await fetch(chrome.runtime.getURL('src/team/environment.json'));
    if (!res.ok) return;
    bundle = await res.json();
  } catch {
    return; // not a team build
  }
  const storage = chromeStorage('local');
  const memory = createMemory(storage, createAudit(storage));
  const stored = await storage.get(TEAM_VERSION_KEY, '');
  const r = await memory.syncBundle(bundle, stored).catch((e) => {
    console.warn('OpenTriage: team environment sync failed', e);
    return null;
  });
  if (r) await storage.set(TEAM_VERSION_KEY, r.version);
}
chrome.runtime.onStartup.addListener(syncTeamEnvironment);

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
  await syncTeamEnvironment();
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: 'opentriage-add-tab',
      title: 'Add this tab to the OpenTriage session',
      contexts: ['page', 'frame', 'action'],
    });
    chrome.contextMenus.create({
      id: 'opentriage-investigate-selection',
      title: 'Investigate selection with OpenTriage',
      contexts: ['selection'],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (!tab) return;
  // sidePanel.open must be called synchronously inside the user gesture.
  const opening = chrome.sidePanel.open({ tabId: tab.id }).catch(() => {});

  if (info.menuItemId === 'opentriage-add-tab') {
    tabSession.add(tab.id).then(() => opening).catch(() => {});
    return;
  }

  if (info.menuItemId === 'opentriage-investigate-selection') {
    // Hand the selection to the side panel. It is untrusted page text and is
    // wrapped as such before it reaches the model.
    tabSession.add(tab.id).catch(() => {});
    chrome.storage.session.set({
      'ot.pendingSelection': {
        text: String(info.selectionText || '').slice(0, 20000),
        url: tab.url,
        tabId: tab.id,
        at: Date.now(),
      },
    });
  }
});
