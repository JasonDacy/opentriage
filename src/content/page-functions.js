// Functions injected into console pages with chrome.scripting.executeScript.
// Each one must be fully self-contained: it is serialised and run inside the
// page, so it cannot reference anything outside its own body.

/**
 * Read the visible text and interactive elements of the current frame.
 * Elements are tagged with data-ot-ref so later clicks can find them.
 */
export function snapshotFrame(opts) {
  const MAX_TEXT = (opts && opts.maxText) || 30000;
  const MAX_ELEMENTS = (opts && opts.maxElements) || 250;
  const out = { url: location.href, title: document.title, text: '', elements: [], truncated: false };
  if (!document.body) return out;

  const isVisible = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== 'hidden' && cs.display !== 'none' && Number(cs.opacity) > 0.05;
  };

  // Text, including open shadow roots (web-component heavy consoles).
  const parts = [document.body.innerText || ''];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
  let node = walker.currentNode;
  let shadowCount = 0;
  while (node && shadowCount < 200) {
    if (node.shadowRoot) {
      shadowCount++;
      const t = Array.from(node.shadowRoot.children)
        .map((c) => c.innerText || c.textContent || '')
        .join('\n');
      if (t.trim()) parts.push(t);
    }
    node = walker.nextNode();
  }
  let text = parts.join('\n').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n');
  if (text.length > MAX_TEXT) {
    text = text.slice(0, MAX_TEXT);
    out.truncated = true;
  }
  out.text = text;

  // Interactive elements.
  const selector = [
    'a[href]', 'button', 'input:not([type=hidden])', 'select', 'textarea', 'summary',
    '[role=button]', '[role=link]', '[role=tab]', '[role=menuitem]', '[role=menuitemradio]', '[role=checkbox]',
    '[role=option]', '[role=treeitem]', '[role=row][tabindex]', '[role=gridcell][tabindex]', '[role=searchbox]',
    '[role=combobox]', '[contenteditable=true]',
  ].join(',');
  const roots = [document];
  document.querySelectorAll('*').forEach((el) => {
    if (el.shadowRoot && roots.length < 200) roots.push(el.shadowRoot);
  });
  let counter = Number(document.documentElement.getAttribute('data-ot-counter') || '0');
  for (const root of roots) {
    for (const el of root.querySelectorAll(selector)) {
      if (out.elements.length >= MAX_ELEMENTS) break;
      if (!isVisible(el)) continue;
      let ref = el.getAttribute('data-ot-ref');
      if (!ref) {
        counter++;
        ref = String(counter);
        el.setAttribute('data-ot-ref', ref);
      }
      const labelledBy = el.getAttribute('aria-labelledby');
      const labelText = labelledBy
        ? labelledBy
            .split(/\s+/)
            .map((id) => (document.getElementById(id) || {}).innerText || '')
            .join(' ')
        : '';
      const name = (
        el.getAttribute('aria-label') ||
        labelText ||
        (el.labels && el.labels[0] && el.labels[0].innerText) ||
        el.getAttribute('placeholder') ||
        el.getAttribute('title') ||
        el.getAttribute('alt') ||
        ''
      ).trim();
      const inner = (el.innerText || el.value || '').trim().replace(/\s+/g, ' ');
      out.elements.push({
        ref,
        tag: el.tagName.toLowerCase(),
        role: el.getAttribute('role') || '',
        type: el.getAttribute('type') || '',
        name: name.slice(0, 120),
        text: inner.slice(0, 120),
        href: el.tagName === 'A' ? el.href.slice(0, 300) : '',
        disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
      });
    }
  }
  document.documentElement.setAttribute('data-ot-counter', String(counter));
  if (out.elements.length >= MAX_ELEMENTS) out.truncated = true;
  return out;
}

/** Describe one element (used to build the approval card before clicking). */
export function describeElement(ref) {
  const find = (root) => {
    const hit = root.querySelector(`[data-ot-ref="${CSS.escape(ref)}"]`);
    if (hit) return hit;
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) {
        const h = find(el.shadowRoot);
        if (h) return h;
      }
    }
    return null;
  };
  const el = find(document);
  if (!el) return null;
  const form = el.closest && el.closest('form');
  return {
    ref,
    tag: el.tagName.toLowerCase(),
    role: el.getAttribute('role') || '',
    type: el.getAttribute('type') || '',
    name: (el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('placeholder') || '').slice(0, 120),
    text: (el.innerText || el.value || '').trim().replace(/\s+/g, ' ').slice(0, 160),
    inForm: !!form,
  };
}

/** Click an element by ref with a realistic pointer sequence. */
export function clickElement(ref) {
  const find = (root) => {
    const hit = root.querySelector(`[data-ot-ref="${CSS.escape(ref)}"]`);
    if (hit) return hit;
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) {
        const h = find(el.shadowRoot);
        if (h) return h;
      }
    }
    return null;
  };
  const el = find(document);
  if (!el) return { ok: false, error: `No element with ref ${ref}. Take a new snapshot; the page may have changed.` };
  el.scrollIntoView({ block: 'center', inline: 'center' });
  const r = el.getBoundingClientRect();
  const opts = { bubbles: true, cancelable: true, composed: true, clientX: r.x + r.width / 2, clientY: r.y + r.height / 2, view: window };
  el.dispatchEvent(new PointerEvent('pointerdown', opts));
  el.dispatchEvent(new MouseEvent('mousedown', opts));
  el.dispatchEvent(new PointerEvent('pointerup', opts));
  el.dispatchEvent(new MouseEvent('mouseup', opts));
  el.click();
  return { ok: true };
}

/** Type into a field; optionally press Enter. Works with React-style controlled inputs. */
export function typeIntoElement(ref, value, submit) {
  const find = (root) => {
    const hit = root.querySelector(`[data-ot-ref="${CSS.escape(ref)}"]`);
    if (hit) return hit;
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) {
        const h = find(el.shadowRoot);
        if (h) return h;
      }
    }
    return null;
  };
  const el = find(document);
  if (!el) return { ok: false, error: `No element with ref ${ref}. Take a new snapshot.` };
  el.focus();
  if (el.isContentEditable) {
    el.textContent = value;
    el.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true }));
  } else {
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value');
    if (setter && setter.set) setter.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    el.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
  }
  if (submit) {
    const k = { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true, composed: true };
    el.dispatchEvent(new KeyboardEvent('keydown', k));
    el.dispatchEvent(new KeyboardEvent('keypress', k));
    el.dispatchEvent(new KeyboardEvent('keyup', k));
  }
  return { ok: true };
}

/** Scroll the frame or the nearest scrollable ancestor of an element. */
export function scrollFrame(direction, ref) {
  const dy = direction === 'up' ? -0.8 : 0.8;
  if (ref) {
    let el = document.querySelector(`[data-ot-ref="${CSS.escape(ref)}"]`);
    while (el && el !== document.body) {
      const cs = getComputedStyle(el);
      if (/(auto|scroll)/.test(cs.overflowY) && el.scrollHeight > el.clientHeight) {
        el.scrollBy(0, el.clientHeight * dy);
        return { ok: true };
      }
      el = el.parentElement;
    }
  }
  // Fall back to the largest scrollable container (common in SPA consoles).
  let best = document.scrollingElement;
  let bestArea = 0;
  for (const el of document.querySelectorAll('div,main,section')) {
    if (el.scrollHeight > el.clientHeight + 20) {
      const cs = getComputedStyle(el);
      if (!/(auto|scroll)/.test(cs.overflowY)) continue;
      const area = el.clientWidth * el.clientHeight;
      if (area > bestArea) {
        best = el;
        bestArea = area;
      }
    }
  }
  best.scrollBy(0, (best.clientHeight || window.innerHeight) * dy);
  return { ok: true };
}

/** Viewport size in CSS pixels, used to map screenshot pixels to page coordinates. */
export function viewportInfo() {
  return { width: window.innerWidth, height: window.innerHeight, dpr: window.devicePixelRatio || 1 };
}

/** Describe the element at a viewport point (CSS px), descending into open shadow roots. */
export function elementAtPoint(x, y) {
  let el = document.elementFromPoint(x, y);
  while (el && el.shadowRoot) {
    const inner = el.shadowRoot.elementFromPoint(x, y);
    if (!inner || inner === el) break;
    el = inner;
  }
  if (!el) return null;
  if (el.tagName === 'IFRAME' || el.tagName === 'FRAME') {
    return { tag: el.tagName.toLowerCase(), isFrame: true, text: '', name: el.getAttribute('title') || '' };
  }
  // Report the nearest interactive ancestor, which is what a click actually activates.
  const target = el.closest('a,button,input,select,textarea,summary,label,[role],[onclick],[tabindex]') || el;
  return {
    tag: target.tagName.toLowerCase(),
    role: target.getAttribute('role') || '',
    type: target.getAttribute('type') || '',
    name: (target.getAttribute('aria-label') || target.getAttribute('title') || target.getAttribute('placeholder') || '').slice(0, 120),
    text: (target.innerText || target.value || '').trim().replace(/\s+/g, ' ').slice(0, 160),
    href: target.tagName === 'A' ? String(target.href).slice(0, 300) : '',
    isFrame: false,
  };
}

/** Click at a viewport point (CSS px). */
export function clickAtPoint(x, y) {
  let el = document.elementFromPoint(x, y);
  while (el && el.shadowRoot) {
    const inner = el.shadowRoot.elementFromPoint(x, y);
    if (!inner || inner === el) break;
    el = inner;
  }
  if (!el) return { ok: false, error: 'Nothing at that point.' };
  const opts = { bubbles: true, cancelable: true, composed: true, clientX: x, clientY: y, view: window };
  el.dispatchEvent(new PointerEvent('pointerdown', opts));
  el.dispatchEvent(new MouseEvent('mousedown', opts));
  el.dispatchEvent(new PointerEvent('pointerup', opts));
  el.dispatchEvent(new MouseEvent('mouseup', opts));
  el.dispatchEvent(new MouseEvent('click', opts));
  if (typeof el.focus === 'function') el.focus({ preventScroll: true });
  return { ok: true };
}

/** Describe the element a key press would go to (ref, or the focused element). */
export function focusedElement(ref) {
  const el = ref ? document.querySelector(`[data-ot-ref="${CSS.escape(ref)}"]`) : document.activeElement;
  if (!el || el === document.body) return { tag: 'body', text: '', name: '', role: '', type: '' };
  return {
    tag: el.tagName.toLowerCase(),
    role: el.getAttribute('role') || '',
    type: el.getAttribute('type') || '',
    name: (el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.getAttribute('title') || '').slice(0, 120),
    text: (el.innerText || el.value || '').trim().replace(/\s+/g, ' ').slice(0, 160),
  };
}

/** Send a key press to an element (ref) or the focused element. */
export function pressKey(key, ref) {
  const el = ref ? document.querySelector(`[data-ot-ref="${CSS.escape(ref)}"]`) : document.activeElement || document.body;
  if (!el) return { ok: false, error: `No element ${ref}. Take a new snapshot.` };
  const codes = { Enter: 13, Escape: 27, ' ': 32, ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, PageUp: 33, PageDown: 34, Home: 36, End: 35, Tab: 9, Backspace: 8 };
  const init = { key, code: key === ' ' ? 'Space' : key, keyCode: codes[key] || 0, which: codes[key] || 0, bubbles: true, cancelable: true, composed: true };
  if (ref && typeof el.focus === 'function') el.focus();
  el.dispatchEvent(new KeyboardEvent('keydown', init));
  el.dispatchEvent(new KeyboardEvent('keyup', init));
  // Synthetic key events don't trigger default actions; emulate the common ones.
  if ((key === 'Enter' || key === ' ') && /^(BUTTON|A|SUMMARY)$/.test(el.tagName)) el.click();
  if (key === 'PageDown' || key === 'PageUp') window.scrollBy(0, (key === 'PageDown' ? 1 : -1) * window.innerHeight * 0.8);
  return { ok: true };
}

/** Centre of an element (CSS px, this frame's viewport) after scrolling it into view. */
export function elementCenter(ref) {
  const find = (root) => {
    const hit = root.querySelector(`[data-ot-ref="${CSS.escape(ref)}"]`);
    if (hit) return hit;
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) {
        const h = find(el.shadowRoot);
        if (h) return h;
      }
    }
    return null;
  };
  const el = find(document);
  if (!el) return null;
  el.scrollIntoView({ block: 'center', inline: 'center' });
  const r = el.getBoundingClientRect();
  return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
}

/** Focus an element (and select its text) so real keystrokes go to it. */
export function focusRef(ref) {
  const find = (root) => {
    const hit = root.querySelector(`[data-ot-ref="${CSS.escape(ref)}"]`);
    if (hit) return hit;
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) {
        const h = find(el.shadowRoot);
        if (h) return h;
      }
    }
    return null;
  };
  const el = find(document);
  if (!el) return { ok: false, error: `No element ${ref}. Take a new snapshot.` };
  el.scrollIntoView({ block: 'center' });
  el.focus();
  if (typeof el.select === 'function') el.select();
  return { ok: true };
}
