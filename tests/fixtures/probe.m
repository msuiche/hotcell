/* Controlled native calls, not an exploit. Exercises actual Frida/Apple ABIs. */
#import <Foundation/Foundation.h>
#import <PDFKit/PDFKit.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreText/CoreText.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) return 2;
    if (argc == 6) sleep(2);  // allows the watch CLI to attach by PID
    @autoreleasepool {
        // Tests the native libobjc selector hooks as well as CG PDF context.
        PDFDocument *doc = [[PDFDocument alloc] initWithURL:[NSURL fileURLWithPath:@(argv[1])]];
        if (!doc) return 3;
        CTFontRef font = CTFontCreateWithName(CFSTR("Helvetica"), atof(argv[3]), NULL);
        UniChar text = 'A'; CGGlyph glyph;
        if (!CTFontGetGlyphsForCharacters(font, &text, &glyph, 1)) return 4;
        CGPathRef path = CTFontCreatePathForGlyph(font, glyph, NULL);
        CGRect b = CGPathGetBoundingBox(path);
        FILE *out = fopen(argv[2], "w");
        if (!out) return 5;
        fprintf(out, "{\"x0\":%.17g,\"y0\":%.17g,\"w\":%.17g,\"h\":%.17g}",
                b.origin.x, b.origin.y, b.size.width, b.size.height);
        fclose(out);
        CGPathRelease(path); CFRelease(font);
        // Must not inherit stale glyph state, even with an enormous rectangle.
        CGPathRef generic = CGPathCreateWithRect(CGRectMake(10,20,8000000,9000000), NULL);
        volatile CGRect genericBounds = CGPathGetBoundingBox(generic);
        (void)genericBounds;
        CGPathRelease(generic);
        if (atoi(argv[4])) {
            size_t n = (size_t)2 * 1024 * 1024 * 1024;
            void *mem = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
            if (mem == MAP_FAILED) return 6;
            munmap(mem, n);  // reserves address space only, no 2GB physical allocation
        }
        usleep(100000);
    }
    return 0;
}
