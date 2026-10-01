/*
 * expmon-apple — runtime exploit monitor for Apple document/image pipelines.
 * Frida agent: identical script on macOS and iOS; injected into the real
 * renderer/processor processes (QuickLook ext, qlmanage, sips, WhatsApp, Mail,
 * Preview, ...). Emits tagged signals; the host correlates them into verdicts.
 *
 * Modeling the EXPMON philosophy: behavioral rules over signatures, in-process,
 * no sandbox, fail-open with an explicit capability report.
 *
 * First validated behavior target (docs/glyph-grift.md):
 *   CVE-2026-86950 "Great Glyph Grift" — CoreGraphics aa_cache_render
 *   fixed-point bbox corruption, reachable PDFKit -> PaperKit -> CoreGraphics
 *   from a crafted PDF/font (QuickLook/sips/ImageIO delivery path).
 */

'use strict';

/* ------------------------------------------------------------------ state */

var CAPS = { hooks: [], missing: [] };

// Recent-context tags (ms timestamps). Used to enrich every signal with the
// document-delivery context, and by the host to reconstruct exploit chains.
var TAGS = {
  lastPdfOpenAt: 0,
  lastPdfRenderAt: 0,
  lastQuickLookAt: 0,
  lastFontParseAt: 0
};

// per-thread scratch (bbox tracking for glyph anomaly correlation)
var PER_THREAD = {};

var MB = 1024 * 1024;
var PDF_ACTIVE_WINDOW_MS = 5 * 60 * 1000;   // "document recently in flight"
var QL_ACTIVE_WINDOW_MS = 2 * 60 * 1000;
var GLYPH_BBOX_MAX_PX = 1024;               // (bbox range)/4096 fixed-point

/* ---------------------------------------------------------------- helpers */

function nowMs() { return Date.now(); }

function recent(at, windowMs) {
  return at > 0 && (nowMs() - at) <= windowMs;
}

function contextTags() {
  return {
    pdf_open_recent: recent(TAGS.lastPdfOpenAt, PDF_ACTIVE_WINDOW_MS),
    pdf_render_recent: recent(TAGS.lastPdfRenderAt, PDF_ACTIVE_WINDOW_MS),
    quicklook_recent: recent(TAGS.lastQuickLookAt, QL_ACTIVE_WINDOW_MS),
    font_parse_recent: recent(TAGS.lastFontParseAt, PDF_ACTIVE_WINDOW_MS)
  };
}

function stackBrief(ctx, depth) {
  try {
    var frames = Thread.backtrace(ctx.context, Backtracer.ACCURATE);
    return frames.slice(0, depth || 5).map(function (a) {
      var s = DebugSymbol.fromAddress(a);
      var name = (s && (s.name || (s.module ? s.module : null))) || null;
      var mod = (s && s.module) || null;
      if (!name && !mod) { return a.sub(0).toString(); }
      return (mod ? mod + '!' + (name || '?') : name);
    });
  } catch (e) { return []; }
}

function signal(severity, rule, detail, ctx) {
  send({
    type: 'signal',
    severity: severity,
    rule: rule,
    detail: detail || {},
    context: contextTags(),
    ts: nowMs(),
    stack: stackBrief(ctx)
  });
}

function guard(name, fn) {
  try { fn(); CAPS.hooks.push(name); }
  catch (e) {
    CAPS.missing.push(name + ' (' + e.message + ')');
  }
}

function findExport(moduleName, name) {
  try { return Module.findExportByName(moduleName, name); }
  catch (e) { return null; }
}

/* ------------------------------------------------------- document sources */

function hookPdfKit() {
  if (!ObjC.available) { CAPS.missing.push('objc'); return; }
  var cls = ObjC.classes.PDFDocument;
  if (!cls) { CAPS.missing.push('PDFDocument'); return; }

  guard('PDFDocument -initWithData:', function () {
    Interceptor.attach(cls['- initWithData:'].implementation, {
      onEnter: function (args) {
        try {
          var data = new ObjC.Object(args[2]);
          var bytes = data.length().valueOf();
          TAGS.lastPdfOpenAt = nowMs();
          // Low-noise: only surface non-trivial documents as signals.
          if (bytes > 4 * MB) {
            signal('low', 'pdf-opened', {
              bytes: bytes, hook: 'PDFDocument -initWithData:'
            }, this);
          }
        } catch (e) { /* read failure: not our problem */ }
      }
    });
  });

  guard('PDFDocument -initWithURL:', function () {
    Interceptor.attach(cls['- initWithURL:'].implementation, {
      onEnter: function (args) {
        try {
          var url = new ObjC.Object(args[2]);
          TAGS.lastPdfOpenAt = nowMs();
          signal('low', 'pdf-opened-url', {
            url: url.absoluteString().toString(),
            hook: 'PDFDocument -initWithURL:'
          }, this);
        } catch (e) { /* */ }
      }
    });
  });
}

function hookPaperKit() {
  if (!ObjC.available) { CAPS.missing.push('objc'); return; }
  var cls = ObjC.classes.PaperDocument;
  if (!cls) { CAPS.missing.push('PaperDocument'); return; }

  // PaperKit is the second leg of the published chain. Hook every
  // data-ingesting selector we can find; PaperKit internals move between
  // builds, so match by shape, not by exact symbol.
  var methods = cls.$ownMethods;
  for (var i = 0; i < methods.length; i++) {
    (function (sel) {
      if (sel.indexOf('Data') === -1 && sel.indexOf('data') === -1) return;
      guard('PaperDocument ' + sel, function () {
        Interceptor.attach(cls[sel].implementation, {
          onEnter: function (args) {
            TAGS.lastPdfOpenAt = nowMs();   // same "document in flight" tag
            try {
              var data = new ObjC.Object(args[2]);
              var bytes = data.length().valueOf();
              if (bytes > 4 * MB) {
                signal('low', 'paperkit-data', {
                  bytes: bytes, hook: 'PaperDocument ' + sel
                }, this);
              }
            } catch (e) { /* */ }
          }
        });
      });
    })(methods[i]);
  }
}

function hookQuickLook() {
  if (!ObjC.available) { CAPS.missing.push('objc'); return; }
  var cls = ObjC.classes.QLThumbnailGenerator;
  if (!cls) { CAPS.missing.push('QLThumbnailGenerator'); return; }

  var methods = cls.$ownMethods;
  for (var i = 0; i < methods.length; i++) {
    (function (sel) {
      if (sel.indexOf('generateBestRepresentation') === -1 &&
          sel.indexOf('generateRepresentationForRequest') === -1) return;
      guard('QLThumbnailGenerator ' + sel, function () {
        Interceptor.attach(cls[sel].implementation, {
          onEnter: function (args) {
            TAGS.lastQuickLookAt = nowMs();
            // Thumbnail generation means untrusted bytes are being rendered
            // from the delivery channel — always worth one informational tag.
            signal('low', 'quicklook-render', {
              hook: 'QLThumbnailGenerator ' + sel
            }, this);
          }
        });
      });
    })(methods[i]);
  }
}

/* --------------------------------------------------------- image pipeline */

function hookImageIO() {
  var create = findExport('ImageIO', 'CGImageSourceCreateImageAtIndex');
  if (create) {
    var CGImageGetWidth = findExport('CoreGraphics', 'CGImageGetWidth');
    var CGImageGetHeight = findExport('CoreGraphics', 'CGImageGetHeight');
    var wFn = CGImageGetWidth ? new NativeFunction(CGImageGetWidth, 'uint32', ['pointer']) : null;
    var hFn = CGImageGetHeight ? new NativeFunction(CGImageGetHeight, 'uint32', ['pointer']) : null;

    guard('CGImageSourceCreateImageAtIndex', function () {
      Interceptor.attach(create, {
        onLeave: function (retval) {
          var img = retval;
          if (img.isNull()) return;
          try {
            var w = wFn ? wFn(img) : 0;
            var h = hFn ? hFn(img) : 0;
            var pixels = w * h;
            // Image-bomb / decoder-stress behavior: >100 MP single frame.
            if (pixels > 100 * 1000 * 1000) {
              signal('medium', 'image-bomb', {
                width: w, height: h, hook: 'CGImageSourceCreateImageAtIndex'
              }, this);
            }
          } catch (e) { /* */ }
        }
      });
    });
  } else {
    CAPS.missing.push('ImageIO!CGImageSourceCreateImageAtIndex');
  }

  var thumb = findExport('ImageIO', 'CGImageSourceCreateThumbnailAtIndex');
  if (thumb) {
    guard('CGImageSourceCreateThumbnailAtIndex', function () {
      Interceptor.attach(thumb, {
        onEnter: function (args) {
          // thumbnail decode of untrusted container: mark context only
          TAGS.lastQuickLookAt = nowMs();
        }
      });
    });
  }
}

/* --------------------------------------------------- font rendering chain */

// The Great Glyph Grift sink: aa_cache_render is a local (non-exported)
// symbol inside CoreGraphics on every build we can check — so we watch the
// exported APIs that sit on the published backtrace around it:
//   CGPathGetBoundingBox            <- corrupted bbox tracking (root cause)
//   CTFontCreatePathForGlyph        <- glyph path construction entry
//   CGFontCreateWithDataProvider    <- font program ingestion
//   CTFontCreateWithGraphicsFont    <- CG font -> CT font bridge
// and report any export we cannot resolve honestly in the capability event.

function hookFontChain() {
  // 1. ingestion
  var fontCreate = findExport('CoreGraphics', 'CGFontCreateWithDataProvider');
  if (fontCreate) {
    guard('CGFontCreateWithDataProvider', function () {
      Interceptor.attach(fontCreate, {
        onLeave: function (retval) {
          if (retval.isNull()) return;
          TAGS.lastFontParseAt = nowMs();
          var ctx = contextTags();
          if (ctx.pdf_open_recent) {
            signal('medium', 'pdf-embedded-font', {
              hook: 'CGFontCreateWithDataProvider'
            }, this);
          }
        }
      });
    });
  } else {
    CAPS.missing.push('CoreGraphics!CGFontCreateWithDataProvider');
  }

  var ctBridge = findExport('CoreText', 'CTFontCreateWithGraphicsFont');
  if (ctBridge) {
    guard('CTFontCreateWithGraphicsFont', function () {
      Interceptor.attach(ctBridge, {
        onEnter: function () { TAGS.lastFontParseAt = nowMs(); }
      });
    });
  }

  // 2. glyph path construction entry (marks per-thread font context)
  var pathForGlyph = findExport('CoreText', 'CTFontCreatePathForGlyph');
  if (pathForGlyph) {
    guard('CTFontCreatePathForGlyph', function () {
      Interceptor.attach(pathForGlyph, {
        onEnter: function (args) {
          var t = PER_THREAD[this.threadId] || (PER_THREAD[this.threadId] = {});
          t.inGlyphPath = true;
          t.glyph = (args[1] && args[1].toInt32()) || 0;
        }
      });
    });
  }

  // 3. the anomaly: corrupted bounding-box tracking. The vulnerable code
  // derives the coverage buffer as width_px = (bbox_max_x - bbox_min_x)/4096
  // from path operations; a corrupted range here is the exploit's fingerprint.
  var bbox = findExport('CoreGraphics', 'CGPathGetBoundingBox');
  if (bbox) {
    guard('CGPathGetBoundingBox (glyph-anomaly)', function () {
      Interceptor.attach(bbox, {
        onLeave: function (retval) {
          // CGRect is returned by value: retval is the sret pointer.
          // origin.x @0, origin.y @8, size.width @16, size.height @24
          var x0 = retval.readDouble();
          var y0 = retval.add(8).readDouble();
          var w = retval.add(16).readDouble();
          var h = retval.add(24).readDouble();
          var t = PER_THREAD[this.threadId] || (PER_THREAD[this.threadId] = {});
          t.bbox = { x0: x0, y0: y0, w: w, h: h };

          var bad = false;
          var why = [];
          if (!isFinite(w) || !isFinite(h)) { bad = true; why.push('non-finite-bbox'); }
          if (w < 0 || h < 0) { bad = true; why.push('negative-bbox'); }
          var wpx = w / 4096, hpx = h / 4096;
          if (wpx > GLYPH_BBOX_MAX_PX || hpx > GLYPH_BBOX_MAX_PX) {
            bad = true; why.push('oversized-glyph-bbox');
          }
          if (bad) {
            signal('high', 'glyph-path-anomaly', {
              bbox: t.bbox, width_px: wpx, height_px: hpx, why: why,
              glyph: ('glyph' in t) ? t.glyph : null,
              in_glyph_path: !!t.inGlyphPath,
              hook: 'CGPathGetBoundingBox'
            }, this);
          }
        }
      });
    });
  } else {
    CAPS.missing.push('CoreGraphics!CGPathGetBoundingBox');
  }

  // 4. pdf page render — completes the published chain legs for correlation
  var drawPdf = findExport('CoreGraphics', 'CGContextDrawPDFPage');
  if (drawPdf) {
    guard('CGContextDrawPDFPage', function () {
      Interceptor.attach(drawPdf, {
        onEnter: function () { TAGS.lastPdfRenderAt = nowMs(); }
      });
    });
  }

  // 5. the sink itself — reported (not pretend-hooked) if not resolvable.
  var sink = findExport('CoreGraphics', 'aa_cache_render');
  if (sink) {
    guard('CoreGraphics!aa_cache_render', function () {
      Interceptor.attach(sink, {
        onEnter: function () {
          signal('medium', 'aa-cache-render-hit', { hook: 'aa_cache_render' }, this);
        }
      });
    });
  } else {
    CAPS.missing.push('CoreGraphics!aa_cache_render (local symbol; watch export backtrace proxies)');
  }
}

/* ------------------------------------------------- memory exploit primitives */

// EXPMON-class primitives, kept loud-but-simple:
//  - huge anonymous maps  -> heap spray prep
//  - W^X transitions      -> shellcode landing
function hookMemoryPrimitives() {
  var mmap = findExport('libsystem_kernel.dylib', 'mmap');
  if (mmap) {
    guard('mmap (anon >=128MB)', function () {
      Interceptor.attach(mmap, {
        onEnter: function (args) {
          var len = args[1].toInt32();
          var prot = args[2].toInt32();
          var flags = args[3].toInt32();
          var fd = args[4].toInt32();
          // MAP_ANON on darwin = 0x1000; anonymous, read/write, file-less.
          if (fd === -1 && (flags & 0x1000) && (prot & 0x3) &&
              len >= 128 * MB) {
            signal('medium', 'big-anon-map', {
              bytes: len, prot: prot, hook: 'mmap'
            }, this);
          }
        }
      });
    });
  } else {
    CAPS.missing.push('libsystem_kernel.dylib!mmap');
  }

  var mprotect = findExport('libsystem_kernel.dylib', 'mprotect');
  if (mprotect) {
    guard('mprotect (->RWX)', function () {
      Interceptor.attach(mprotect, {
        onEnter: function (args) {
          var prot = args[2].toInt32();
          if ((prot & 0x1) && (prot & 0x2) && (prot & 0x4)) {
            signal('high', 'rwx-transition', {
              bytes: args[1].toInt32(), hook: 'mprotect'
            }, this);
          }
        }
      });
    });
  } else {
    CAPS.missing.push('libsystem_kernel.dylib!mprotect');
  }
}

/* ----------------------------------------------------------------- load */

function boot() {
  hookPdfKit();
  hookPaperKit();
  hookQuickLook();
  hookImageIO();
  hookFontChain();
  hookMemoryPrimitives();

  send({
    type: 'capability',
    platform: Process.platform,
    arch: Process.arch,
    pid: Process.id,
    hooks: CAPS.hooks,
    missing: CAPS.missing,
    version: 1
  });
}

boot();

rpc.exports = {
  status: function () { return CAPS; }
};
