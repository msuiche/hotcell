/* hotcell: Frida 17 native hooks for Apple document and image pipelines.
 * No bundled ObjC bridge is required: selectors resolve through libobjc.
 * Exported glyph paths are a heuristic; internal rasterizer coverage is not implied.
 */
'use strict';

const installed = new Map();
const missing = new Map();
const callbackErrors = new Set();
const hits = {};
const tags = {pdfOpen: 0, pdfRender: 0, quicklook: 0, font: 0};
const MB = 1024 * 1024;
const GLYPH_BBOX_MAX_UNITS = 1024;
let installing = false;

function findExport(module, name) {
  const m = Process.findModuleByName(module);
  return m ? m.findExportByName(name) : null;
}
function native(module, name, result, args) {
  const p = findExport(module, name);
  return p ? new NativeFunction(p, result, args, {traps: 'none'}) : null;
}
function contextTags() {
  const t = Date.now();
  function recent(at, window) { return at > 0 && t - at <= window; }
  return {
    pdf_open_recent: recent(tags.pdfOpen, 300000),
    pdf_render_recent: recent(tags.pdfRender, 300000),
    quicklook_recent: recent(tags.quicklook, 120000),
    font_parse_recent: recent(tags.font, 300000)
  };
}
function signal(severity, rule, detail, invocation) {
  let stack = [];
  try {
    stack = Thread.backtrace(invocation.context, Backtracer.ACCURATE).slice(0, 5)
      .map(a => DebugSymbol.fromAddress(a).toString());
  } catch (_) {}
  send({type: 'signal', severity, rule, detail, context: contextTags(),
        ts: Date.now() / 1000, ts_unit: 's', stack});
}
function attach(name, address, callbacks) {
  if (installed.has(name)) return;
  if (address === null) { missing.set(name, 'unavailable'); return; }
  const wrapped = {};
  Object.keys(callbacks).forEach(phase => {
    wrapped[phase] = function (...args) {
      if (phase === 'onEnter' || !callbacks.onEnter) hits[name] = (hits[name] || 0) + 1;
      try { return callbacks[phase].apply(this, args); }
      catch (e) {
        if (!callbackErrors.has(name)) {
          callbackErrors.add(name);
          send({type: 'error', detail: {description: name + ': ' + e.message}});
        }
      }
    };
  });
  try {
    installed.set(name, Interceptor.attach(address, wrapped));
    missing.delete(name);
  } catch (e) { missing.set(name, e.message); }
}
function hook(module, name, callbacks) {
  attach(name, findExport(module, name), callbacks);
}
function capabilities() {
  return {type: 'capability', platform: Process.platform, arch: Process.arch,
          pid: Process.id, hooks: Array.from(installed.keys()),
          missing: Array.from(missing, ([name, reason]) => name + ' (' + reason + ')'),
          hits, version: 2};
}

// Resolve only known selectors. Never call arbitrary *data* methods or guess
// the type of args[2]. This works with both Frida's bare runtime and its REPL.
function installObjC() {
  const getClass = native('libobjc.A.dylib', 'objc_getClass', 'pointer', ['pointer']);
  const sel = native('libobjc.A.dylib', 'sel_registerName', 'pointer', ['pointer']);
  const getMethod = native('libobjc.A.dylib', 'class_getInstanceMethod', 'pointer', ['pointer', 'pointer']);
  const getImp = native('libobjc.A.dylib', 'method_getImplementation', 'pointer', ['pointer']);
  const specs = [
    ['PDFDocument', 'initWithData:', 'pdf-opened', 'pdfOpen'],
    ['PDFDocument', 'initWithURL:', 'pdf-opened-url', 'pdfOpen'],
    ['PaperDocument', 'initWithData:', 'paperkit-data', 'pdfOpen'],
    ['QLThumbnailGenerator', 'generateBestRepresentationForRequest:completionHandler:', 'quicklook-render', 'quicklook'],
    ['QLThumbnailGenerator', 'generateRepresentationsForRequest:updateHandler:', 'quicklook-render', 'quicklook']
  ];
  specs.forEach(([cls, selector, rule, tag]) => {
    const name = cls + ' -' + selector;
    if (installed.has(name)) return;
    let address = null;
    if (getClass && sel && getMethod && getImp) {
      const klass = getClass(Memory.allocUtf8String(cls));
      if (!klass.isNull()) {
        const method = getMethod(klass, sel(Memory.allocUtf8String(selector)));
        if (!method.isNull()) address = getImp(method);
      }
    }
    attach(name, address, {onEnter() {
      tags[tag] = Date.now();
      signal('low', rule, {hook: name}, this);
    }});
  });
}

function installNative() {
  if (installing) return;
  installing = true;
  try {
    const completion = Process.mainModule.findExportByName('hotcell_render_complete');
    if (completion) attach('hotcell_render_complete', completion, {
      onEnter(args) {
        signal('low', 'render-complete', {status: args[0].toInt32(),
               count: parseInt(args[1].toString(), 16)}, this);
        send(capabilities());
        // Keep the helper alive until the host has received the final signal.
        // Fast parser failures otherwise race process teardown and lose events.
        recv('hotcell:complete-ack', function () {}).wait();
      }
    });
    ['CGPDFDocumentCreateWithURL', 'CGPDFDocumentCreateWithProvider'].forEach(name => {
      hook('CoreGraphics', name, {
        onEnter() { tags.pdfOpen = Date.now(); },
        onLeave(retval) {
          if (!retval.isNull()) signal('low', 'pdf-opened', {hook: name}, this);
        }
      });
    });
    hook('CoreGraphics', 'CGContextDrawPDFPage', {
      onEnter() { tags.pdfRender = Date.now(); },
      onLeave() { signal('low', 'pdf-rendered', {hook: 'CGContextDrawPDFPage'}, this); }
    });
    const width = native('CoreGraphics', 'CGImageGetWidth', 'ulong', ['pointer']);
    const height = native('CoreGraphics', 'CGImageGetHeight', 'ulong', ['pointer']);
    ['CGImageSourceCreateImageAtIndex', 'CGImageSourceCreateThumbnailAtIndex'].forEach(name => {
      hook('ImageIO', name, {
        onEnter() { if (name.indexOf('Thumbnail') !== -1) tags.quicklook = Date.now(); },
        onLeave(retval) {
          if (retval.isNull() || !width || !height) return;
          const w = Number(width(retval)), h = Number(height(retval));
          signal('low', 'image-decoded', {width: w, height: h, hook: name}, this);
          if (w * h > 100000000)
            signal('medium', 'image-bomb', {width: w, height: h, hook: name}, this);
        }
      });
    });
    hook('CoreGraphics', 'CGFontCreateWithDataProvider', {
      onLeave(retval) {
        if (retval.isNull()) return;
        tags.font = Date.now();
        if (contextTags().pdf_open_recent)
          signal('medium', 'pdf-embedded-font', {hook: 'CGFontCreateWithDataProvider'}, this);
      }
    });
    hook('CoreText', 'CTFontCreateWithGraphicsFont', {onEnter() { tags.font = Date.now(); }});

    // CGRect is a homogeneous floating-point aggregate on arm64, not a return
    // pointer. Let libffi handle its ABI and bypass hooks during the pure query.
    const scalar = Process.pointerSize === 8 ? 'double' : 'float';
    const getBBox = native('CoreGraphics', 'CGPathGetBoundingBox',
                           [[scalar, scalar], [scalar, scalar]], ['pointer']);
    function inspectPath(path, invocation, glyph) {
      if (!getBBox || path.isNull()) return;
      const b = getBBox(path);
      const w = b[1][0], h = b[1][1];
      // Public CGPath coordinates are user-space units, NOT 20.12 fixed point.
      const why = [];
      if (!isFinite(w) || !isFinite(h)) why.push('non-finite-bbox');
      if (w < 0 || h < 0) why.push('negative-bbox');
      if (w > GLYPH_BBOX_MAX_UNITS || h > GLYPH_BBOX_MAX_UNITS) why.push('oversized-glyph-bbox');
      if (why.length) signal('high', 'glyph-path-anomaly', {
        bbox: {x0: b[0][0], y0: b[0][1], w, h},
        units: 'user-space', why, glyph, in_glyph_path: true,
        hook: 'CGPathGetBoundingBox'
      }, invocation);
    }
    if (!getBBox) missing.set('CTFontCreatePathForGlyph', 'CGPathGetBoundingBox query unavailable');
    if (getBBox) hook('CoreText', 'CTFontCreatePathForGlyph', {
      onEnter(args) {
        this.glyph = args[1].toUInt32() & 0xffff;
      },
      onLeave(retval) {
        // Inspect the final scaled path only. Intermediate font-parser paths
        // are in design units (often 2048/em) and routinely exceed 1024.
        inspectPath(retval, this, this.glyph);
      }
    });
    hook('CoreGraphics', 'aa_cache_render', {
      onEnter() { signal('medium', 'aa-cache-render-hit', {hook: 'aa_cache_render'}, this); }
    });
    hook('libsystem_kernel.dylib', 'mmap', {
      onEnter(args) {
        this.bytes = parseInt(args[1].toString(), 16);
        this.prot = args[2].toInt32();
        this.reportMap = args[4].toInt32() === -1 && (args[3].toInt32() & 0x1000) &&
                         (this.prot & 3) === 3 && this.bytes >= 128 * MB;
      },
      onLeave(retval) {
        if (this.reportMap && !retval.equals(ptr(-1)))
          signal('medium', 'big-anon-map', {bytes: this.bytes, prot: this.prot, hook: 'mmap'}, this);
      }
    });
    hook('libsystem_kernel.dylib', 'mprotect', {
      onEnter(args) {
        this.bytes = parseInt(args[1].toString(), 16);
        this.rwx = (args[2].toInt32() & 7) === 7;
      },
      onLeave(retval) {
        if (this.rwx && retval.toInt32() === 0)
          signal('high', 'rwx-transition', {bytes: this.bytes, hook: 'mprotect'}, this);
      }
    });
  } finally { installing = false; }
}

installNative();
installObjC();
send(capabilities());
let refreshPending = false;
const observer = Process.attachModuleObserver({
  onAdded(module) {
    if (!/CoreGraphics|CoreText|ImageIO|PDFKit|PaperKit|QuickLook|libobjc/.test(module.name)) return;
    installNative();
    // Objective-C class registration can finish after dyld's notification.
    if (!refreshPending) {
      refreshPending = true;
      setImmediate(() => { refreshPending = false; installObjC(); send(capabilities()); });
    }
  }
});
rpc.exports = {status() { return capabilities(); }};
