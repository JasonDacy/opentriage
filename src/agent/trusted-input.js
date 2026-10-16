// Trusted input through the Chrome DevTools Protocol (chrome.debugger).
//
// Simulated DOM events (element.click(), synthetic KeyboardEvent) have
// isTrusted=false, and some consoles ignore them. CDP Input.* events are
// indistinguishable from a real mouse and keyboard. The cost: Chrome shows
// "OpenTriage started debugging this browser" while attached, and the
// `debugger` permission cannot be optional — so this ships only in the
// "trusted input" build and is off until the analyst turns it on.
//
// We attach just-in-time to the tab being acted on and detach when the
// agent's turn ends.

const PROTOCOL = '1.3';

export function trustedInputAvailable() {
  return typeof chrome !== 'undefined' && !!chrome.debugger;
}

export function createTrustedInput() {
  const attached = new Set();
  if (trustedInputAvailable()) {
    chrome.debugger.onDetach.addListener((src) => attached.delete(src.tabId));
  }

  async function attach(tabId) {
    if (attached.has(tabId)) return;
    await chrome.debugger.attach({ tabId }, PROTOCOL);
    attached.add(tabId);
    await send(tabId, 'Page.enable').catch(() => {});
    await send(tabId, 'DOM.enable').catch(() => {});
  }

  function send(tabId, method, params = {}) {
    return chrome.debugger.sendCommand({ tabId }, method, params);
  }

  async function mouseClick(tabId, x, y) {
    await attach(tabId);
    const base = { x, y, button: 'left', clickCount: 1, pointerType: 'mouse' };
    await send(tabId, 'Input.dispatchMouseEvent', { type: 'mouseMoved', x, y, pointerType: 'mouse' });
    await send(tabId, 'Input.dispatchMouseEvent', { ...base, type: 'mousePressed', buttons: 1 });
    await send(tabId, 'Input.dispatchMouseEvent', { ...base, type: 'mouseReleased', buttons: 0 });
  }

  const KEYDEF = {
    Enter: { code: 'Enter', keyCode: 13, text: '\r' },
    Escape: { code: 'Escape', keyCode: 27 },
    Tab: { code: 'Tab', keyCode: 9 },
    ' ': { code: 'Space', keyCode: 32, text: ' ' },
    Backspace: { code: 'Backspace', keyCode: 8 },
    ArrowUp: { code: 'ArrowUp', keyCode: 38 },
    ArrowDown: { code: 'ArrowDown', keyCode: 40 },
    ArrowLeft: { code: 'ArrowLeft', keyCode: 37 },
    ArrowRight: { code: 'ArrowRight', keyCode: 39 },
    PageUp: { code: 'PageUp', keyCode: 33 },
    PageDown: { code: 'PageDown', keyCode: 34 },
    Home: { code: 'Home', keyCode: 36 },
    End: { code: 'End', keyCode: 35 },
    a: { code: 'KeyA', keyCode: 65, text: 'a' },
  };

  async function key(tabId, k, modifiers = 0) {
    await attach(tabId);
    const d = KEYDEF[k];
    if (!d) throw new Error(`Unsupported key ${k}`);
    const common = { key: k, code: d.code, windowsVirtualKeyCode: d.keyCode, nativeVirtualKeyCode: d.keyCode, modifiers };
    await send(tabId, 'Input.dispatchKeyEvent', { ...common, type: d.text && !modifiers ? 'keyDown' : 'rawKeyDown', ...(d.text && !modifiers ? { text: d.text, unmodifiedText: d.text } : {}) });
    await send(tabId, 'Input.dispatchKeyEvent', { ...common, type: 'keyUp' });
  }

  async function insertText(tabId, text) {
    await attach(tabId);
    await send(tabId, 'Input.insertText', { text });
  }

  /** Select all in the focused field (Ctrl/Cmd+A) so typing replaces it. */
  async function selectAll(tabId) {
    const mac = /Mac/i.test(navigator.platform || '');
    await key(tabId, 'a', mac ? 4 : 2);
  }

  /**
   * Offset (CSS px, main-frame viewport) of a child frame's content box,
   * located by matching the frame URL in the CDP frame tree. Only first-level
   * frames are supported; deeper frames fall back to simulated input.
   */
  async function frameOffset(tabId, frameUrl) {
    await attach(tabId);
    const { frameTree } = await send(tabId, 'Page.getFrameTree');
    const child = (frameTree.childFrames || []).find((c) => c.frame.url === frameUrl) || (frameTree.childFrames || []).find((c) => frameUrl.startsWith(c.frame.url.split('#')[0]));
    if (!child) return null;
    const { backendNodeId } = await send(tabId, 'DOM.getFrameOwner', { frameId: child.frame.id });
    const { model } = await send(tabId, 'DOM.getBoxModel', { backendNodeId });
    return { x: model.content[0], y: model.content[1] };
  }

  async function screenshot(tabId) {
    await attach(tabId);
    const { data } = await send(tabId, 'Page.captureScreenshot', { format: 'jpeg', quality: 80 });
    return 'data:image/jpeg;base64,' + data;
  }

  async function releaseAll() {
    for (const tabId of [...attached]) {
      try {
        await chrome.debugger.detach({ tabId });
      } catch {
        /* already detached */
      }
      attached.delete(tabId);
    }
  }

  return { mouseClick, key, insertText, selectAll, frameOffset, screenshot, releaseAll, isAttached: (id) => attached.has(id) };
}
