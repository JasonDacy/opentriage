// The investigation session's tabs live in one Chrome tab group titled
// "OpenTriage". A tab is in the session exactly when it is in that group, so
// the analyst can add tabs from the side panel, from the right-click menu, or
// by dragging a tab into the group — and remove them the same ways.
//
// The agent can only see and act on tabs in the group. Tabs it opens itself
// are added to the group automatically.
//
// `api` is the `chrome` namespace (or a fake in tests).

export const GROUP_TITLE = 'OpenTriage';
export const GROUP_COLOR = 'blue';
const GROUP_KEY = 'ot.sessionGroupId';

export function createTabSession(api = globalThis.chrome) {
  async function storedGroupId() {
    const r = await api.storage.session.get(GROUP_KEY);
    const id = r[GROUP_KEY];
    if (typeof id !== 'number') return null;
    try {
      await api.tabGroups.get(id);
      return id;
    } catch {
      await api.storage.session.remove(GROUP_KEY);
      return null;
    }
  }

  async function findExistingGroup() {
    // Re-adopt a group with our title if the stored id was lost (e.g. after a browser restart).
    const groups = await api.tabGroups.query({ title: GROUP_TITLE });
    return groups.length ? groups[0].id : null;
  }

  async function groupId() {
    const id = (await storedGroupId()) ?? (await findExistingGroup());
    if (id !== null) await api.storage.session.set({ [GROUP_KEY]: id });
    return id;
  }

  const toTab = (t) => ({ id: t.id, url: t.url || '', title: t.title || '', active: !!t.active, windowId: t.windowId });

  return {
    groupId,

    /** Tabs currently in the session, in tab-strip order. */
    async list() {
      const id = await groupId();
      if (id === null) return [];
      const tabs = await api.tabs.query({ groupId: id });
      return tabs.sort((a, b) => a.windowId - b.windowId || a.index - b.index).map(toTab);
    },

    async has(tabId) {
      const id = await groupId();
      if (id === null) return false;
      try {
        const t = await api.tabs.get(tabId);
        return t.groupId === id;
      } catch {
        return false;
      }
    },

    /** Add tabs to the session group, creating the group if needed. */
    async add(tabIds) {
      const ids = (Array.isArray(tabIds) ? tabIds : [tabIds]).filter((x) => Number.isInteger(x));
      if (!ids.length) return null;
      let id = await groupId();
      if (id === null) {
        id = await api.tabs.group({ tabIds: ids });
        await api.tabGroups.update(id, { title: GROUP_TITLE, color: GROUP_COLOR });
      } else {
        await api.tabs.group({ groupId: id, tabIds: ids });
      }
      await api.storage.session.set({ [GROUP_KEY]: id });
      return id;
    },

    /** Remove tabs from the session (they stay open, just ungrouped). */
    async remove(tabIds) {
      const ids = (Array.isArray(tabIds) ? tabIds : [tabIds]).filter((x) => Number.isInteger(x));
      if (ids.length) await api.tabs.ungroup(ids);
    },

    /** Tabs that could be added: normal web tabs not already in the session. */
    async candidates() {
      const id = await groupId();
      const tabs = await api.tabs.query({});
      return tabs.filter((t) => t.groupId !== id && /^https?:/.test(t.url || '')).map(toTab);
    },
  };
}
