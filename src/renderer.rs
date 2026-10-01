//! Native Apple rendering in the executable's private `__render` subprocess.
use anyhow::Result;
use std::path::Path;

// A stable exported symbol for the agent; retained even in optimized builds.
#[no_mangle]
#[inline(never)]
pub extern "C" fn hotcell_render_complete(status: i32, count: usize) {
    std::hint::black_box((status, count));
}
pub fn run(input: &Path, output: &Path) -> i32 {
    match render(input, output) {
        Ok(count) => {
            hotcell_render_complete(0, count);
            0
        }
        Err(e) => {
            hotcell_render_complete(2, 0);
            eprintln!("hotcell renderer: {e:#}");
            2
        }
    }
}
#[cfg(not(target_os = "macos"))]
pub fn render(_: &Path, _: &Path) -> Result<usize> {
    anyhow::bail!("runtime file scans require macOS; use --static-only on other hosts")
}
#[cfg(target_os = "macos")]
pub fn render(input: &Path, output: &Path) -> Result<usize> {
    apple::render(input, output)
}

#[cfg(target_os = "macos")]
mod apple {
    use super::*;
    use anyhow::{bail, Context};
    use std::{
        ffi::{c_char, c_void, CString},
        io::Read,
        os::unix::ffi::OsStrExt,
        ptr,
    };
    type Ref = *mut c_void;
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Point {
        x: f64,
        y: f64,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Size {
        width: f64,
        height: f64,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Rect {
        origin: Point,
        size: Size,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Transform {
        a: f64,
        b: f64,
        c: f64,
        d: f64,
        tx: f64,
        ty: f64,
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFURLCreateFromFileSystemRepresentation(
            alloc: Ref,
            bytes: *const u8,
            len: isize,
            is_dir: u8,
        ) -> Ref;
        fn CFStringCreateWithCString(alloc: Ref, text: *const c_char, encoding: u32) -> Ref;
        fn CFDictionaryCreate(
            alloc: Ref,
            keys: *const Ref,
            values: *const Ref,
            count: isize,
            key_cb: *const c_void,
            val_cb: *const c_void,
        ) -> Ref;
        fn CFRelease(value: Ref);
        static kCFBooleanTrue: Ref;
        static kCFTypeDictionaryKeyCallBacks: [usize; 6];
        static kCFTypeDictionaryValueCallBacks: [usize; 5];
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGPDFDocumentCreateWithURL(url: Ref) -> Ref;
        fn CGPDFDocumentGetNumberOfPages(doc: Ref) -> usize;
        fn CGPDFDocumentIsEncrypted(doc: Ref) -> bool;
        fn CGPDFDocumentGetPage(doc: Ref, page: usize) -> Ref;
        fn CGPDFDocumentRelease(doc: Ref);
        fn CGPDFPageGetBoxRect(page: Ref, kind: u32) -> Rect;
        fn CGPDFPageGetDrawingTransform(
            page: Ref,
            kind: u32,
            rect: Rect,
            rotate: i32,
            preserve: bool,
        ) -> Transform;
        fn CGColorSpaceCreateDeviceRGB() -> Ref;
        fn CGColorSpaceRelease(space: Ref);
        fn CGBitmapContextCreate(
            data: Ref,
            width: usize,
            height: usize,
            bits: usize,
            row_bytes: usize,
            space: Ref,
            info: u32,
        ) -> Ref;
        fn CGContextConcatCTM(ctx: Ref, transform: Transform);
        fn CGContextDrawPDFPage(ctx: Ref, page: Ref);
        fn CGContextFlush(ctx: Ref);
        fn CGContextRelease(ctx: Ref);
        fn CGBitmapContextCreateImage(ctx: Ref) -> Ref;
        fn CGImageRelease(image: Ref);
    }
    #[link(name = "ImageIO", kind = "framework")]
    extern "C" {
        fn CGImageSourceCreateWithURL(url: Ref, options: Ref) -> Ref;
        fn CGImageSourceGetCount(source: Ref) -> usize;
        fn CGImageSourceCreateImageAtIndex(source: Ref, index: usize, options: Ref) -> Ref;
        fn CGImageDestinationCreateWithURL(url: Ref, kind: Ref, count: usize, options: Ref) -> Ref;
        fn CGImageDestinationAddImage(dest: Ref, image: Ref, options: Ref);
        fn CGImageDestinationFinalize(dest: Ref) -> bool;
        static kCGImageSourceShouldCacheImmediately: Ref;
    }
    // Keep the same CoreText framework available to the agent's font hooks.
    #[link(name = "CoreText", kind = "framework")]
    extern "C" {}
    struct Owned {
        raw: Ref,
        release: unsafe extern "C" fn(Ref),
    }
    impl Owned {
        // Each caller supplies the matching Create/Copy API's release function.
        unsafe fn new(raw: Ref, release: unsafe extern "C" fn(Ref), what: &str) -> Result<Self> {
            if raw.is_null() {
                bail!("{what}");
            }
            Ok(Self { raw, release })
        }
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe { (self.release)(self.raw) }
        }
    }
    unsafe fn file_url(path: &Path) -> Result<Owned> {
        let bytes = path.as_os_str().as_bytes();
        Owned::new(
            CFURLCreateFromFileSystemRepresentation(
                ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len().try_into()?,
                0,
            ),
            CFRelease,
            "cannot create file URL",
        )
    }
    unsafe fn write_png(image: Ref, url: Ref) -> Result<()> {
        let name = CString::new("public.png")?;
        let kind = Owned::new(
            CFStringCreateWithCString(ptr::null_mut(), name.as_ptr(), 0x08000100),
            CFRelease,
            "cannot create image type",
        )?;
        let dest = Owned::new(
            CGImageDestinationCreateWithURL(url, kind.raw, 1, ptr::null_mut()),
            CFRelease,
            "cannot create PNG destination",
        )?;
        CGImageDestinationAddImage(dest.raw, image, ptr::null_mut());
        if !CGImageDestinationFinalize(dest.raw) {
            bail!("cannot write PNG preview");
        }
        Ok(())
    }
    unsafe fn pdf(input: Ref, output: Ref) -> Result<usize> {
        let doc = Owned::new(
            CGPDFDocumentCreateWithURL(input),
            CGPDFDocumentRelease,
            "input is not a readable PDF",
        )?;
        let pages = CGPDFDocumentGetNumberOfPages(doc.raw);
        if pages == 0 || CGPDFDocumentIsEncrypted(doc.raw) {
            bail!("PDF is empty or encrypted");
        }
        for index in 1..=pages {
            let page = CGPDFDocumentGetPage(doc.raw, index);
            if page.is_null() {
                bail!("missing PDF page {index}");
            }
            let rect = CGPDFPageGetBoxRect(page, 0);
            let (w, h) = (rect.size.width, rect.size.height);
            if !w.is_finite() || !h.is_finite() || w <= 0.0 || h <= 0.0 {
                bail!("invalid PDF page dimensions");
            }
            let scale = 1024.0 / w.max(h);
            let width = (w * scale).ceil().clamp(1.0, 1024.0) as usize;
            let height = (h * scale).ceil().clamp(1.0, 1024.0) as usize;
            let space = Owned::new(
                CGColorSpaceCreateDeviceRGB(),
                CGColorSpaceRelease,
                "cannot create color space",
            )?;
            let ctx = Owned::new(
                CGBitmapContextCreate(ptr::null_mut(), width, height, 8, width * 4, space.raw, 1),
                CGContextRelease,
                "cannot create bitmap context",
            )?;
            let destination = Rect {
                origin: Point { x: 0.0, y: 0.0 },
                size: Size {
                    width: width as f64,
                    height: height as f64,
                },
            };
            CGContextConcatCTM(
                ctx.raw,
                CGPDFPageGetDrawingTransform(page, 0, destination, 0, true),
            );
            CGContextDrawPDFPage(ctx.raw, page);
            CGContextFlush(ctx.raw);
            if index == 1 {
                let image = Owned::new(
                    CGBitmapContextCreateImage(ctx.raw),
                    CGImageRelease,
                    "cannot create PDF preview",
                )?;
                write_png(image.raw, output)?;
            }
        }
        Ok(pages)
    }
    unsafe fn image(input: Ref, output: Ref) -> Result<usize> {
        let source = Owned::new(
            CGImageSourceCreateWithURL(input, ptr::null_mut()),
            CFRelease,
            "unsupported or malformed image",
        )?;
        let keys = [kCGImageSourceShouldCacheImmediately];
        let values = [kCFBooleanTrue];
        let options = Owned::new(
            CFDictionaryCreate(
                ptr::null_mut(),
                keys.as_ptr(),
                values.as_ptr(),
                1,
                ptr::addr_of!(kCFTypeDictionaryKeyCallBacks).cast(),
                ptr::addr_of!(kCFTypeDictionaryValueCallBacks).cast(),
            ),
            CFRelease,
            "cannot create decode options",
        )?;
        let frames = CGImageSourceGetCount(source.raw);
        if frames == 0 {
            bail!("image has no frames");
        }
        for index in 0..frames {
            let image = Owned::new(
                CGImageSourceCreateImageAtIndex(source.raw, index, options.raw),
                CGImageRelease,
                "image frame could not be decoded",
            )?;
            if index == 0 {
                write_png(image.raw, output)?;
            }
        }
        Ok(frames)
    }
    pub fn render(input: &Path, output: &Path) -> Result<usize> {
        let mut bytes = [0u8; 1024];
        let len = std::fs::File::open(input)
            .context("open input")?
            .read(&mut bytes)?;
        let is_pdf = bytes[..len].windows(5).any(|w| w == b"%PDF-");
        // Framework objects remain owned until all borrowed page/image references
        // are no longer used. The host isolates rendering in a separate process.
        unsafe {
            let input = file_url(input)?;
            let output = file_url(output)?;
            if is_pdf {
                pdf(input.raw, output.raw)
            } else {
                image(input.raw, output.raw)
            }
        }
    }
}
