SEE INDEX.HTML FOR AN EASILY BROWSED HYPERTEXT VERSION OF THIS MANUAL.

* * *

                                    gd 1.3
                                       
A graphics library for fast GIF creation

Follow this link to the latest version of this document.

  Table of Contents
  
     * Credits and license terms
     * What's new in version 1.3?
     * What is gd?
     * What if I want to use another programming language?
     * What else do I need to use gd?
     * How do I get gd?
     * How do I build gd?
     * gd basics: using gd in your program
     * webgif: a useful example
     * Function and type reference by category
     * About the additional .gd image file format
     * Please tell us you're using gd!
     * If you have problems
     * Alphabetical quick index
       
   Up to the Boutell.Com, Inc. Home Page
   
  Credits and license terms
  
   In order to resolve any possible confusion regarding the authorship of
   gd, the following copyright statement covers all of the authors who
   have required such a statement. Although his LZW compression code no
   longer appears in gd, the authors wish to thank David Rowley for the
   original LZW-based GIF compression code, which has been removed due to
   patent concerns. If you are aware of any oversights in this copyright
   notice, please contact Thomas Boutell who will be pleased to correct
   them.

COPYRIGHT STATEMENT FOLLOWS THIS LINE

     Portions copyright 1994, 1995, 1996, 1997, 1998, by Cold Spring
     Harbor Laboratory. Funded under Grant P41-RR02188 by the National
     Institutes of Health.
     
     Portions copyright 1996, 1997, 1998, by Boutell.Com, Inc.
     
     GIF decompression code copyright 1990, 1991, 1993, by David Koblas
     (koblas@netcom.com).
     
     Non-LZW-based GIF compression code copyright 1998, by Hutchison
     Avenue Software Corporation (http://www.hasc.com/, info@hasc.com).
     
     Permission has been granted to copy and distribute gd in any
     context, including a commercial application, provided that this
     notice is present in user-accessible supporting documentation.
     
     This does not affect your ownership of the derived work itself, and
     the intent is to assure proper credit for the authors of gd, not to
     interfere with your productive use of gd. If you have questions,
     ask. "Derived works" includes all programs that utilize the
     library. Credit must be given in user-accessible documentation.
     
     Permission to use, copy, modify, and distribute this software and
     its documentation for any purpose and without fee is hereby
     granted, provided that the above copyright notice appear in all
     copies and that both that copyright notice and this permission
     notice appear in supporting documentation. This software is
     provided "as is" without express or implied warranty.
     
END OF COPYRIGHT STATEMENT

  What is gd?
  
   gd is a graphics library. It allows your code to quickly draw images
   complete with lines, arcs, text, multiple colors, cut and paste from
   other images, and flood fills, and write out the result as a .GIF
   file. This is particularly useful in World Wide Web applications,
   where .GIF is the format used for inline images.
   
   gd is not a paint program. If you are looking for a paint program, you
   are looking in the wrong place. If you are not a programmer, you are
   looking in the wrong place.
   
   gd does not provide for every possible desirable graphics operation.
   It is not necessary or desirable for gd to become a kitchen-sink
   graphics package, but version 1.3 incorporates most of the commonly
   requested features for an 8-bit 2D package. Support for scalable
   fonts, and truecolor images, JPEG and PNG is planned for version 2.0.
   Version 1.3 was released to correct longstanding bugs and provide an
   LZW-free GIF compression routine.
   
  What if I want to use another programming language?
  
    Perl
    
   gd can also be used from Perl, courtesy of Lincoln Stein's GD.pm
   library, which uses gd as the basis for a set of Perl 5.x classes.
   GD.pm is based on gd 1.1.1 but gd 1.2 should be compatible.
   
    Any Language
    
   There are, at the moment, at least three simple interpreters that
   perform gd operations. You can output the desired commands to a simple
   text file from whatever scripting language you prefer to use, then
   invoke the interpreter.
   
   These packages are based on gd 1.2 as of this writing but should be
   compatible with gd 1.3 with minimal tweaking.
     * tgd, by Bradley K. Sherman
     * fly, by Martin Gleeson
       
  What's new in version 1.3?
  
   Version 1.3 features the following changes:
   
   Non-LZW-based GIF compression code
          Version 1.3 contains GIF compression code that uses simple Run
          Length Encoding instead of LZW compression, while still
          retaining compatibility with normal LZW-based GIF decoders
          (your browser will still like your GIFs). LZW compression is
          patented by Unisys. This is why there have been no new versions
          of gd for a long time. THANKS to Hutchison Avenue Software
          Corporation for contributing this code. THE NEW CODE PRODUCES
          LARGER GIFS AND IS NOT WELL SUITED TO PHOTOGRAPHIC IMAGES. THIS
          IS A LEGAL ISSUE. IT IS NOT A QUESTION OF TECHNICAL SKILL.
          PLEASE DON'T COMPLAIN ABOUT THE SIZE OF GIF OUTPUT. THANKS!
          
   8-bit fonts, and 8-bit font support
          This improves support for European languages. Thanks are due to
          Honza Pazdziora and also to Jan Pazdziora . Also see the
          provided bdftogd Perl script if you wish to convert fixed-width
          X11 fonts to gd fonts.
          
   16-bit font support (no fonts provided)
          Although no such fonts are provided in the distribution, fonts
          containing more than 256 characters should work if the
          gdImageString16 and gdImageStringUp16 routines are used.
          
   Improvements to the "webgif" example/utility
          The "webgif" utility is now a slightly more useful application.
          Thanks to Brian Dowling for this code.
          
   Corrections to the color resolution field of GIF output
          Thanks to Bruno Aureli.
          
   Fixed polygon fills
          A one-line patch for the infamous polygon fill bug, courtesy of
          Jim Mason. I believe this fix is sufficient. However, if you
          find a situation where polygon fills still fail to behave
          properly, please send code that demonstrates the problem, and a
          fix if you have one. Verifying the fix is important.
          
   Row-major, not column-major
          Internally, gd now represents the array of pixels as an array
          of rows of pixels, rather than an array of columns of pixels.
          This improves the performance of compression and decompression
          routines slightly, because horizontally adjacent pixels are now
          next to each other in memory. This should not affect properly
          written gd applications, but applications that directly
          manipulate the pixels array will require changes.
          
  What else do I need to use gd?
  
   To use gd, you will need an ANSI C compiler. All popular Windows 95
   and NT C compilers are ANSI C compliant. Any full-ANSI-standard C
   compiler should be adequate. The cc compiler released with SunOS 4.1.3
   is not an ANSI C compiler. Most Unix users who do not already have gcc
   should get it. gcc is free, ANSI compliant and a de facto industry
   standard. Ask your ISP why it is missing.
   
   You will also want a GIF viewer, if you do not already have one for
   your system, since you will need a good way to check the results of
   your work. Any web browser will work, but you might be happier with a
   package like Lview Pro for Windows or xv for X. There are GIF viewers
   available for every graphics-capable computer out there, so consult
   newsgroups relevant to your particular system.
   
  How do I get gd?
  
    By HTTP
    
     * Gzipped Tar File (Unix)
     * .ZIP File (Windows)
       
    By FTP
    
     * Gzipped Tar File (Unix)
     * .ZIP File (Windows)
       
  How do I build gd?
  
   In order to build gd, you must first unpack the archive you have
   downloaded. If you are not familiar with tar and gunzip (Unix) or ZIP
   (Windows), please consult with an experienced user of your system.
   Sorry, we cannot answer questions about basic Internet skills.
   
   Unpacking the archive will produce a directory called "gd1.3".
   
    For Unix
    
   cd to the gd1.3 directory and examine the Makefile, which you will
   probably need to change slightly depending on your operating system
   and your needs.
   
    For Windows, Mac, Et Cetera
    
   Create a project using your favorite programming environment. Copy all
   of the gd files to the project directory. Add gd.c to your project.
   Add other source files as appropriate. Learning the basic skills of
   creating projects with your chosen C environment is up to you.
   
   Now, to build the demonstration program, just type "make gddemo" if
   you are working in a command-line environment, or build a project that
   includes gddemo.c if you are using a graphical environment. If all
   goes well, the program "gddemo" will be compiled and linked without
   incident. Depending on your system you may need to edit the Makefile.
   Understanding the basic techniques of compiling and linking programs
   on your system is up to you.
   
   You have now built a demonstration program which shows off the
   capabilities of gd. To see it in action, type "gddemo".
   
   gddemo should execute without incident, creating the file demoout.gif.
   (Note there is also a file named demoin.gif, which is provided in the
   package as part of the demonstration.)
   
   Display demoout.gif in your GIF viewer. The image should be 128x128
   pixels and should contain an image of the space shuttle with quite a
   lot of graphical elements drawn on top of it.
   
   (If you are missing the demoin.gif file, the other items should appear
   anyway.)
   
   Look at demoin.gif to see the original space shuttle image which was
   scaled and copied into the output image.
   
  gd basics: using gd in your program
  
   gd lets you create GIF images on the fly. To use gd in your program,
   include the file gd.h, and link with the libgd.a library produced by
   "make libgd.a", under Unix. Under other operating systems you will add
   gd.c to your own project.
   
   If you want to use the provided fonts, include gdfontt.h, gdfonts.h,
   gdfontmb.h, gdfontl.h and/or gdfontg.h. If you are not using the
   provided Makefile and/or a library-based approach, be sure to include
   the source modules as well in your project. (They may be too large for
   16-bit memory models, that is, 16-bit DOS and Windows.)
   
   Here is a short example program. (For a more advanced example, see
   gddemo.c, included in the distribution. gddemo.c is NOT the same
   program; it demonstrates additional features!)
   
/* Bring in gd library functions */
#include "gd.h"

/* Bring in standard I/O so we can output the GIF to a file */
#include <stdio.h>

int main() {
        /* Declare the image */
        gdImagePtr im;
        /* Declare an output file */
        FILE *out;
        /* Declare color indexes */
        int black;
        int white;

        /* Allocate the image: 64 pixels across by 64 pixels tall */
        im = gdImageCreate(64, 64);

        /* Allocate the color black (red, green and blue all minimum).
                Since this is the first color in a new image, it will
                be the background color. */
        black = gdImageColorAllocate(im, 0, 0, 0);

        /* Allocate the color white (red, green and blue all maximum). */
        white = gdImageColorAllocate(im, 255, 255, 255);
        
        /* Draw a line from the upper left to the lower right,
                using white color index. */
        gdImageLine(im, 0, 0, 63, 63, white);

        /* Open a file for writing. "wb" means "write binary", important
                under MSDOS, harmless under Unix. */
        out = fopen("test.gif", "wb");

        /* Output the image to the disk file. */
        gdImageGif(im, out);

        /* Close the file. */
        fclose(out);

        /* Destroy the image in memory. */
        gdImageDestroy(im);
}

   When executed, this program creates an image, allocates two colors
   (the first color allocated becomes the background color), draws a
   diagonal line (note that 0, 0 is the upper left corner), writes the
   image to a GIF file, and destroys the image.
   
   The above example program should give you an idea of how the package
   works. gd provides many additional functions, which are listed in the
   following reference chapters, complete with code snippets
   demonstrating each. There is also an alphabetical index.
   
  Webgif: a more powerful gd example
  
   Webgif is a simple utility program to manipulate GIFs from the command
   line. It is written for Unix and similar command-line systems, but
   should be easily adapted for other environments. Webgif allows you to
   set transparency and interlacing and output interesting information
   about the GIF in question.
   
   webgif.c is provided in the distribution. Unix users can simply type
   "make webgif" to compile the program. Type "webgif" with no arguments
   to see the available options.
   
Function and type reference

     * Types
     * Image creation, destruction, loading and saving
     * Drawing, styling, brushing, tiling and filling functions
     * Query functions (not color-related)
     * Font and text-handling functions
     * Color handling functions
     * Copying and resizing functions
     * Miscellaneous Functions
     * Constants
       
  Types
  
   gdImage(TYPE)
          The data structure in which gd stores images. gdImageCreate
          returns a pointer to this type, and the other functions expect
          to receive a pointer to this type as their first argument. You
          may read the members sx (size on X axis), sy (size on Y axis),
          colorsTotal (total colors), red (red component of colors; an
          array of 256 integers between 0 and 255), green (green
          component of colors, as above), blue (blue component of colors,
          as above), and transparent (index of transparent color, -1 if
          none); please do so using the macros provided. Do NOT set the
          members directly from your code; use the functions provided.
          

typedef struct {
        unsigned char ** pixels;
        int sx;
        int sy;
        int colorsTotal;
        int red[gdMaxColors];
        int green[gdMaxColors];
        int blue[gdMaxColors];
        int open[gdMaxColors];
        int transparent;
} gdImage;

   gdImagePtr (TYPE)
          A pointer to an image structure. gdImageCreate returns this
          type, and the other functions expect it as the first argument.
          
   gdFont (TYPE)
          A font structure. Used to declare the characteristics of a
          font. Plese see the files gdfontl.c and gdfontl.h for an
          example of the proper declaration of this structure. You can
          provide your own font data by providing such a structure and
          the associated pixel array. You can determine the width and
          height of a single character in a font by examining the w and h
          members of the structure. If you will not be creating your own
          fonts, you will not need to concern yourself with the rest of
          the components of this structure.
          

typedef struct {
        /* # of characters in font */
        int nchars;
        /* First character is numbered... (usually 32 = space) */
        int offset;
        /* Character width and height */
        int w;
        int h;
        /* Font data; array of characters, one row after another.
                Easily included in code, also easily loaded from
                data files. */
        char *data;
} gdFont;

   gdFontPtr (TYPE)
          A pointer to a font structure. Text-output functions expect
          these as their second argument, following the gdImagePtr
          argument. Two such pointers are declared in the provided
          include files gdfonts.h and gdfontl.h.
          
   gdPoint (TYPE)
          Represents a point in the coordinate space of the image; used
          by gdImagePolygon and gdImageFilledPolygon.
          

typedef struct {
        int x, y;
} gdPoint, *gdPointPtr;

   gdPointPtr (TYPE)
          A pointer to a gdPoint structure; passed as an argument to
          gdImagePolygon and gdImageFilledPolygon.
          
  Image creation, destruction, loading and saving
  
   gdImageCreate(sx, sy) (FUNCTION)
          gdImageCreate is called to create images. Invoke gdImageCreate
          with the x and y dimensions of the desired image. gdImageCreate
          returns a gdImagePtr to the new image, or NULL if unable to
          allocate the image. The image must eventually be destroyed
          using gdImageDestroy().
          

... inside a function ...
gdImagePtr im;
im = gdImageCreate(64, 64);
/* ... Use the image ... */
gdImageDestroy(im);

   gdImageCreateFromGif(FILE *in) (FUNCTION)
          gdImageCreateFromGif is called to load images from GIF format
          files. Invoke gdImageCreateFromGif with an already opened
          pointer to a file containing the desired image.
          gdImageCreateFromGif returns a gdImagePtr to the new image, or
          NULL if unable to load the image (most often because the file
          is corrupt or does not contain a GIF image).
          gdImageCreateFromGif does not close the file. You can inspect
          the sx and sy members of the image to determine its size. The
          image must eventually be destroyed using gdImageDestroy().
          

gdImagePtr im;
... inside a function ...
FILE *in;
in = fopen("mygif.gif", "rb");
im = gdImageCreateFromGif(in);
fclose(in);
/* ... Use the image ... */
gdImageDestroy(im);

   gdImageCreateFromGd(FILE *in) (FUNCTION)
          gdImageCreateFromGd is called to load images from gd format
          files. Invoke gdImageCreateFromGd with an already opened
          pointer to a file containing the desired image in the gd file
          format, which is specific to gd and intended for very fast
          loading. (It is not intended for compression; for compression,
          use GIF.) gdImageCreateFromGd returns a gdImagePtr to the new
          image, or NULL if unable to load the image (most often because
          the file is corrupt or does not contain a gd format image).
          gdImageCreateFromGd does not close the file. You can inspect
          the sx and sy members of the image to determine its size. The
          image must eventually be destroyed using gdImageDestroy().
          

... inside a function ...
gdImagePtr im;
FILE *in;
in = fopen("mygd.gd", "rb");
im = gdImageCreateFromGd(in);
fclose(in);
/* ... Use the image ... */
gdImageDestroy(im);

   gdImageCreateFromXbm(FILE *in) (FUNCTION)
          gdImageCreateFromXbm is called to load images from X bitmap
          format files. Invoke gdImageCreateFromXbm with an already
          opened pointer to a file containing the desired image.
          gdImageCreateFromXbm returns a gdImagePtr to the new image, or
          NULL if unable to load the image (most often because the file
          is corrupt or does not contain an X bitmap format image).
          gdImageCreateFromXbm does not close the file. You can inspect
          the sx and sy members of the image to determine its size. The
          image must eventually be destroyed using gdImageDestroy().
          

... inside a function ...
gdImagePtr im;
FILE *in;
in = fopen("myxbm.xbm", "rb");
im = gdImageCreateFromXbm(in);
fclose(in);
/* ... Use the image ... */
gdImageDestroy(im);

   gdImageDestroy(gdImagePtr im) (FUNCTION)
          gdImageDestroy is used to free the memory associated with an
          image. It is important to invoke gdImageDestroy before exiting
          your program or assigning a new image to a gdImagePtr variable.
          

... inside a function ...
gdImagePtr im;
im = gdImageCreate(10, 10);
/* ... Use the image ... */
/* Now destroy it */
gdImageDestroy(im);

   void gdImageGif(gdImagePtr im, FILE *out) (FUNCTION)
          gdImageGif outputs the specified image to the specified file in
          GIF format. The file must be open for writing. Under MSDOS, it
          is important to use "wb" as opposed to simply "w" as the mode
          when opening the file, and under Unix there is no penalty for
          doing so. gdImageGif does not close the file; your code must do
          so.
          

... inside a function ...
gdImagePtr im;
int black, white;
FILE *out;
/* Create the image */
im = gdImageCreate(100, 100);
/* Allocate background */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Allocate drawing color */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Draw rectangle */
gdImageRectangle(im, 0, 0, 99, 99, black);
/* Open output file in binary mode */
out = fopen("rect.gif", "wb");
/* Write GIF */
gdImageGif(im, out);
/* Close file */
fclose(out);
/* Destroy image */
gdImageDestroy(im);

   void gdImageGd(gdImagePtr im, FILE *out) (FUNCTION)
          gdImageGd outputs the specified image to the specified file in
          the gd image format. The file must be open for writing. Under
          MSDOS, it is important to use "wb" as opposed to simply "w" as
          the mode when opening the file, and under Unix there is no
          penalty for doing so. gdImageGif does not close the file; your
          code must do so.
          
          The gd image format is intended for fast reads and writes of
          images your program will need frequently to build other images.
          It is not a compressed format, and is not intended for general
          use.
          

... inside a function ...
gdImagePtr im;
int black, white;
FILE *out;
/* Create the image */
im = gdImageCreate(100, 100);
/* Allocate background */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Allocate drawing color */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Draw rectangle */
gdImageRectangle(im, 0, 0, 99, 99, black);
/* Open output file in binary mode */
out = fopen("rect.gd", "wb");
/* Write gd format file */
gdImageGd(im, out);
/* Close file */
fclose(out);
/* Destroy image */
gdImageDestroy(im);

  Drawing Functions
  
   void gdImageSetPixel(gdImagePtr im, int x, int y, int color)
          (FUNCTION)
          gdImageSetPixel sets a pixel to a particular color index.
          Always use this function or one of the other drawing functions
          to access pixels; do not access the pixels of the gdImage
          structure directly.
          

... inside a function ...
gdImagePtr im;
int black;
int white;
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Set a pixel near the center. */
gdImageSetPixel(im, 50, 50, white);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

   void gdImageLine(gdImagePtr im, int x1, int y1, int x2, int y2, int
          color) (FUNCTION)
          gdImageLine is used to draw a line between two endpoints (x1,y1
          and x2, y2). The line is drawn using the color index specified.
          Note that the color index can be an actual color returned by
          gdImageColorAllocate or one of gdStyled, gdBrushed or
          gdStyledBrushed.
          

... inside a function ...
gdImagePtr im;
int black;
int white;
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Draw a line from the upper left corner to the lower right corner. */
gdImageLine(im, 0, 0, 99, 99, white);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

   void gdImageDashedLine(gdImagePtr im, int x1, int y1, int x2, int y2,
          int color) (FUNCTION)
          gdImageDashedLine is provided solely for backwards
          compatibility with gd 1.0. New programs should draw dashed
          lines using the normal gdImageLine function and the new
          gdImageSetStyle function.
          
          gdImageDashedLine is used to draw a dashed line between two
          endpoints (x1,y1 and x2, y2). The line is drawn using the color
          index specified. The portions of the line that are not drawn
          are left transparent so the background is visible.
          

... inside a function ...
gdImagePtr im;
int black;
int white;
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Draw a dashed line from the upper left corner to the lower right corner. */
gdImageDashedLine(im, 0, 0, 99, 99);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

   void gdImagePolygon(gdImagePtr im, gdPointPtr points, int pointsTotal,
          int color) (FUNCTION)
          gdImagePolygon is used to draw a polygon with the verticies (at
          least 3) specified, using the color index specified. See also
          gdImageFilledPolygon.
          

... inside a function ...
gdImagePtr im;
int black;
int white;
/* Points of polygon */
gdPoint points[3];
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Draw a triangle. */
points[0].x = 50;
points[0].y = 0;
points[1].x = 99;
points[1].y = 99;
points[2].x = 0;
points[2].y = 99;
gdImagePolygon(im, points, 3, white);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

   void gdImageRectangle(gdImagePtr im, int x1, int y1, int x2, int y2,
          int color) (FUNCTION)
          gdImageRectangle is used to draw a rectangle with the two
          corners (upper left first, then lower right) specified, using
          the color index specified.
          

... inside a function ...
gdImagePtr im;
int black;
int white;
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Draw a rectangle occupying the central area. */
gdImageRectangle(im, 25, 25, 74, 74, white);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

   void gdImageFilledPolygon(gdImagePtr im, gdPointPtr points, int
          pointsTotal, int color) (FUNCTION)
          gdImageFilledPolygon is used to fill a polygon with the
          verticies (at least 3) specified, using the color index
          specified. See also gdImagePolygon.
          

... inside a function ...
gdImagePtr im;
int black;
int white;
int red;
/* Points of polygon */
gdPoint points[3];
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Allocate the color red. */
red = gdImageColorAllocate(im, 255, 0, 0);
/* Draw a triangle. */
points[0].x = 50;
points[0].y = 0;
points[1].x = 99;
points[1].y = 99;
points[2].x = 0;
points[2].y = 99;
/* Paint it in white */
gdImageFilledPolygon(im, points, 3, white);
/* Outline it in red; must be done second */
gdImagePolygon(im, points, 3, red);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

   void gdImageFilledRectangle(gdImagePtr im, int x1, int y1, int x2, int
          y2, int color) (FUNCTION)
          gdImageFilledRectangle is used to draw a solid rectangle with
          the two corners (upper left first, then lower right) specified,
          using the color index specified.
          

... inside a function ...
gdImagePtr im;
int black;
int white;
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = int gdImageColorAllocate(im, 255, 255, 255);
/* Draw a filled rectangle occupying the central area. */
gdImageFilledRectangle(im, 25, 25, 74, 74, white);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

   void gdImageArc(gdImagePtr im, int cx, int cy, int w, int h, int s,
          int e, int color) (FUNCTION)
          gdImageArc is used to draw a partial ellipse centered at the
          given point, with the specified width and height in pixels. The
          arc begins at the position in degrees specified by s and ends
          at the position specified by e. The arc is drawn in the color
          specified by the last argument. A circle can be drawn by
          beginning from 0 degrees and ending at 360 degrees, with width
          and height being equal. e must be greater than s. Values
          greater than 360 are interpreted modulo 360.
          

... inside a function ...
gdImagePtr im;
int black;
int white;
im = gdImageCreate(100, 50);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Inscribe an ellipse in the image. */
gdImageArc(im, 50, 25, 98, 48, 0, 360, white);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

   void gdImageFillToBorder(gdImagePtr im, int x, int y, int border, int
          color) (FUNCTION)
          gdImageFillToBorder floods a portion of the image with the
          specified color, beginning at the specified point and stopping
          at the specified border color. For a way of flooding an area
          defined by the color of the starting point, see gdImageFill.
          
          The border color cannot be a special color such as gdTiled; it
          must be a proper solid color. The fill color can be, however.
          
          Note that gdImageFillToBorder is recursive. It is not the most
          naive implementation possible, and the implementation is
          expected to improve, but there will always be degenerate cases
          in which the stack can become very deep. This can be a problem
          in MSDOS and MS Windows environments. (Of course, in a Unix or
          NT environment with a proper stack, this is not a problem at
          all.)
          

... inside a function ...
gdImagePtr im;
int black;
int white;
int red;
im = gdImageCreate(100, 50);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Allocate the color red. */
red = gdImageColorAllocate(im, 255, 0, 0);
/* Inscribe an ellipse in the image. */
gdImageArc(im, 50, 25, 98, 48, 0, 360, white);
/* Flood-fill the ellipse. Fill color is red, border color is
        white (ellipse). */
gdImageFillToBorder(im, 50, 50, white, red);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

   void gdImageFill(gdImagePtr im, int x, int y, int color) (FUNCTION)
          gdImageFill floods a portion of the image with the specified
          color, beginning at the specified point and flooding the
          surrounding region of the same color as the starting point. For
          a way of flooding a region defined by a specific border color
          rather than by its interior color, see gdImageFillToBorder.
          
          The fill color can be gdTiled, resulting in a tile fill using
          another image as the tile. However, the tile image cannot be
          transparent. If the image you wish to fill with has a
          transparent color index, call gdImageTransparent on the tile
          image and set the transparent color index to -1 to turn off its
          transparency.
          
          Note that gdImageFill is recursive. It is not the most naive
          implementation possible, and the implementation is expected to
          improve, but there will always be degenerate cases in which the
          stack can become very deep. This can be a problem in MSDOS and
          MS Windows environments. (Of course, in a Unix or NT
          environment with a proper stack, this is not a problem at all.)
          

... inside a function ...
gdImagePtr im;
int black;
int white;
int red;
im = gdImageCreate(100, 50);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Allocate the color red. */
red = gdImageColorAllocate(im, 255, 0, 0);
/* Inscribe an ellipse in the image. */
gdImageArc(im, 50, 25, 98, 48, 0, 360, white);
/* Flood-fill the ellipse. Fill color is red, and will replace the
        black interior of the ellipse. */
gdImageFill(im, 50, 50, red);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

   void gdImageSetBrush(gdImagePtr im, gdImagePtr brush) (FUNCTION)
          A "brush" is an image used to draw wide, shaped strokes in
          another image. Just as a paintbrush is not a single point, a
          brush image need not be a single pixel. Any gd image can be
          used as a brush, and by setting the transparent color index of
          the brush image with gdImageColorTransparent, a brush of any
          shape can be created. All line-drawing functions, such as
          gdImageLine and gdImagePolygon, will use the current brush if
          the special "color" gdBrushed or gdStyledBrushed is used when
          calling them.
          
          gdImageSetBrush is used to specify the brush to be used in a
          particular image. You can set any image to be the brush. If the
          brush image does not have the same color map as the first
          image, any colors missing from the first image will be
          allocated. If not enough colors can be allocated, the closest
          colors already available will be used. This allows arbitrary
          GIFs to be used as brush images. It also means, however, that
          you should not set a brush unless you will actually use it; if
          you set a rapid succession of different brush images, you can
          quickly fill your color map, and the results will not be
          optimal.
          
          You need not take any special action when you are finished with
          a brush. As for any other image, if you will not be using the
          brush image for any further purpose, you should call
          gdImageDestroy. You must not use the color gdBrushed if the
          current brush has been destroyed; you can of course set a new
          brush to replace it.
          

... inside a function ...
gdImagePtr im, brush;
FILE *in;
int black;
im = gdImageCreate(100, 100);
/* Open the brush GIF. For best results, portions of the
        brush that should be transparent (ie, not part of the
        brush shape) should have the transparent color index. */
in = fopen("star.gif", "rb");
brush = gdImageCreateFromGif(in);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
gdImageSetBrush(im, brush);
/* Draw a line from the upper left corner to the lower right corner
        using the brush. */
gdImageLine(im, 0, 0, 99, 99, gdBrushed);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);
/* Destroy the brush image */
gdImageDestroy(brush);

   void gdImageSetTile(gdImagePtr im, gdImagePtr tile) (FUNCTION)
          A "tile" is an image used to fill an area with a repeated
          pattern. Any gd image can be used as a tile, and by setting the
          transparent color index of the tile image with
          gdImageColorTransparent, a tile that allows certain parts of
          the underlying area to shine through can be created. All
          region-filling functions, such as gdImageFill and
          gdImageFilledPolygon, will use the current tile if the special
          "color" gdTiled is used when calling them.
          
          gdImageSetTile is used to specify the tile to be used in a
          particular image. You can set any image to be the tile. If the
          tile image does not have the same color map as the first image,
          any colors missing from the first image will be allocated. If
          not enough colors can be allocated, the closest colors already
          available will be used. This allows arbitrary GIFs to be used
          as tile images. It also means, however, that you should not set
          a tile unless you will actually use it; if you set a rapid
          succession of different tile images, you can quickly fill your
          color map, and the results will not be optimal.
          
          You need not take any special action when you are finished with
          a tile. As for any other image, if you will not be using the
          tile image for any further purpose, you should call
          gdImageDestroy. You must not use the color gdTiled if the
          current tile has been destroyed; you can of course set a new
          tile to replace it.
          

... inside a function ...
gdImagePtr im, tile;
FILE *in;
int black;
im = gdImageCreate(100, 100);
/* Open the tile GIF. For best results, portions of the
        tile that should be transparent (ie, allowing the
        background to shine through) should have the transparent
        color index. */
in = fopen("star.gif", "rb");
tile = gdImageCreateFromGif(in);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
gdImageSetTile(im, tile);
/* Fill an area using the tile. */
gdImageFilledRectangle(im, 25, 25, 75, 75, gdTiled);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);
/* Destroy the tile image */
gdImageDestroy(tile);

   void gdImageSetStyle(gdImagePtr im, int *style, int styleLength)
          (FUNCTION)
          It is often desirable to draw dashed lines, dotted lines, and
          other variations on a broken line. gdImageSetStyle can be used
          to set any desired series of colors, including a special color
          that leaves the background intact, to be repeated during the
          drawing of a line.
          
          To use gdImageSetStyle, create an array of integers and assign
          them the desired series of color values to be repeated. You can
          assign the special color value gdTransparent to indicate that
          the existing color should be left unchanged for that particular
          pixel (allowing a dashed line to be attractively drawn over an
          existing image).
          
          Then, to draw a line using the style, use the normal
          gdImageLine function with the special color value gdStyled.
          
          As of version 1.1.1, the style array is copied when you set the
          style, so you need not be concerned with keeping the array
          around indefinitely. This should not break existing code that
          assumes styles are not copied.
          
          You can also combine styles and brushes to draw the brush image
          at intervals instead of in a continuous stroke. When creating a
          style for use with a brush, the style values are interpreted
          differently: zero (0) indicates pixels at which the brush
          should not be drawn, while one (1) indicates pixels at which
          the brush should be drawn. To draw a styled, brushed line, you
          must use the special color value gdStyledBrushed. For an
          example of this feature in use, see gddemo.c (provided in the
          distribution).
          

gdImagePtr im;
int styleDotted[2], styleDashed[6];
FILE *in;
int black;
int red;
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
red = gdImageColorAllocate(im, 255, 0, 0);
/* Set up dotted style. Leave every other pixel alone. */
styleDotted[0] = red;
styleDotted[1] = gdTransparent;
/* Set up dashed style. Three on, three off. */
styleDashed[0] = red;
styleDashed[1] = red;
styleDashed[2] = red;
styleDashed[3] = gdTransparent;
styleDashed[4] = gdTransparent;
styleDashed[5] = gdTransparent;
/* Set dotted style. Note that we have to specify how many pixels are
        in the style! */
gdImageSetStyle(im, styleDotted, 2);
/* Draw a line from the upper left corner to the lower right corner. */
gdImageLine(im, 0, 0, 99, 99, gdStyled);
/* Now the dashed line. */
gdImageSetStyle(im, styleDashed, 6);
gdImageLine(im, 0, 99, 0, 99, gdStyled);

/* ... Do something with the image, such as saving it to a file ... */

/* Destroy it */
gdImageDestroy(im);

  Query Functions
  
        int gdImageBlue(gdImagePtr im, int color) (MACRO)
                gdImageBlue is a macro which returns the blue component
                of the specified color index. Use this macro rather than
                accessing the structure members directly.
                
        int gdImageGetPixel(gdImagePtr im, int x, int y) (FUNCTION)
                gdImageGetPixel() retrieves the color index of a
                particular pixel. Always use this function to query
                pixels; do not access the pixels of the gdImage structure
                directly.
                

... inside a function ...
FILE *in;
gdImagePtr im;
int c;
in = fopen("mygif.gif", "rb");
im = gdImageCreateFromGif(in);
fclose(in);
c = gdImageGetPixel(im, gdImageSX(im) / 2, gdImageSY(im) / 2);
printf("The value of the center pixel is %d; RGB values are %d,%d,%d\n",
        c, im->red[c], im->green[c], im->blue[c]);
gdImageDestroy(im);

        int gdImageBoundsSafe(gdImagePtr im, int x, int y) (FUNCTION)
                gdImageBoundsSafe returns true (1) if the specified point
                is within the bounds of the image, false (0) if not. This
                function is intended primarily for use by those who wish
                to add functions to gd. All of the gd drawing functions
                already clip safely to the edges of the image.
                

... inside a function ...
gdImagePtr im;
int black;
int white;
im = gdImageCreate(100, 100);
if (gdImageBoundsSafe(im, 50, 50)) {
        printf("50, 50 is within the image bounds\n");
} else {
        printf("50, 50 is outside the image bounds\n");
}
gdImageDestroy(im);

        int gdImageGreen(gdImagePtr im, int color) (MACRO)
                gdImageGreen is a macro which returns the green component
                of the specified color index. Use this macro rather than
                accessing the structure members directly.
                
        int gdImageRed(gdImagePtr im, int color) (MACRO)
                gdImageRed is a macro which returns the red component of
                the specified color index. Use this macro rather than
                accessing the structure members directly.
                
        int gdImageSX(gdImagePtr im) (MACRO)
                gdImageSX is a macro which returns the width of the image
                in pixels. Use this macro rather than accessing the
                structure members directly.
                
        int gdImageSY(gdImagePtr im) (MACRO)
                gdImageSY is a macro which returns the height of the
                image in pixels. Use this macro rather than accessing the
                structure members directly.
                
  Fonts and text-handling functions
  
        void gdImageChar(gdImagePtr im, gdFontPtr font, int x, int y, int
                c, int color) (FUNCTION)
                gdImageChar is used to draw single characters on the
                image. (To draw multiple characters, use gdImageString or
                gdImageString16.) The second argument is a pointer to a
                font definition structure; five fonts are provided with
                gd, gdFontTiny, gdFontSmall, gdFontMediumBold,
                gdFontLarge, and gdFontGiant. You must include the files
                "gdfontt.h", "gdfonts.h", "gdfontmb.h", "gdfontl.h" and
                "gdfontg.h" respectively and (if you are not using a
                library-based approach) link with the corresponding .c
                files to use the provided fonts. The character specified
                by the fifth argument is drawn from left to right in the
                specified color. (See gdImageCharUp for a way of drawing
                vertical text.) Pixels not set by a particular character
                retain their previous color.
                

#include "gd.h"
#include "gdfontl.h"
... inside a function ...
gdImagePtr im;
int black;
int white;
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Draw a character. */
gdImageChar(im, gdFontLarge, 0, 0, 'Q', white);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

        void gdImageCharUp(gdImagePtr im, gdFontPtr font, int x, int y,
                int c, int color) (FUNCTION)
                gdImageCharUp is used to draw single characters on the
                image, rotated 90 degrees. (To draw multiple characters,
                use gdImageStringUp or gdImageStringUp16.) The second
                argument is a pointer to a font definition structure;
                five fonts are provided with gd, gdFontTiny, gdFontSmall,
                gdFontMediumBold, gdFontLarge, and gdFontGiant. You must
                include the files "gdfontt.h", "gdfonts.h", "gdfontmb.h",
                "gdfontl.h" and "gdfontg.h" respectively and (if you are
                not using a library-based approach) link with the
                corresponding .c files to use the provided fonts. The
                character specified by the fifth argument is drawn from
                bottom to top, rotated at a 90-degree angle, in the
                specified color. (See gdImageChar for a way of drawing
                horizontal text.) Pixels not set by a particular
                character retain their previous color.
                

#include "gd.h"
#include "gdfontl.h"
... inside a function ...
gdImagePtr im;
int black;
int white;
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Draw a character upwards so it rests against the top of the image. */
gdImageCharUp(im, gdFontLarge,
        0, gdFontLarge->h, 'Q', white);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

        void gdImageString(gdImagePtr im, gdFontPtr font, int x, int y,
                unsigned char *s, int color) (FUNCTION)
                gdImageString is used to draw multiple characters on the
                image. (To draw single characters, use gdImageChar.) The
                second argument is a pointer to a font definition
                structure; five fonts are provided with gd, gdFontTiny,
                gdFontSmall, gdFontMediumBold, gdFontLarge, and
                gdFontGiant. You must include the files "gdfontt.h",
                "gdfonts.h", "gdfontmb.h", "gdfontl.h" and "gdfontg.h"
                respectively and (if you are not using a library-based
                approach) link with the corresponding .c files to use the
                provided fonts. The null-terminated C string specified by
                the fifth argument is drawn from left to right in the
                specified color. (See gdImageStringUp for a way of
                drawing vertical text.) Pixels not set by a particular
                character retain their previous color.
                

#include "gd.h"
#include "gdfontl.h"
#include <string.h>
... inside a function ...
gdImagePtr im;
int black;
int white;
/* String to draw. */
char *s = "Hello.";
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Draw a centered string. */
gdImageString(im, gdFontLarge,
        im->w / 2 - (strlen(s) * gdFontLarge->w / 2),
        im->h / 2 - gdFontLarge->h / 2,
        s, white);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

        void gdImageString16(gdImagePtr im, gdFontPtr font, int x, int y,
                unsigned short *s, int color) (FUNCTION)
                gdImageString is used to draw multiple 16-bit characters
                on the image. (To draw single characters, use
                gdImageChar.) The second argument is a pointer to a font
                definition structure; five fonts are provided with gd,
                gdFontTiny, gdFontSmall, gdFontMediumBold, gdFontLarge,
                and gdFontGiant. You must include the files "gdfontt.h",
                "gdfonts.h", "gdfontmb.h", "gdfontl.h" and "gdfontg.h"
                respectively and (if you are not using a library-based
                approach) link with the corresponding .c files to use the
                provided fonts. The null-terminated string of characters
                represented as 16-bit unsigned short integers specified
                by the fifth argument is drawn from left to right in the
                specified color. (See gdImageStringUp16 for a way of
                drawing vertical text.) Pixels not set by a particular
                character retain their previous color.
                
                This function was added in gd1.3 to provide a means of
                rendering fonts with more than 256 characters for those
                who have them. A more frequently used routine is
                gdImageString.
                
        void gdImageStringUp(gdImagePtr im, gdFontPtr font, int x, int y,
                unsigned char *s, int color) (FUNCTION)
                gdImageStringUp is used to draw multiple characters on
                the image, rotated 90 degrees. (To draw single
                characters, use gdImageCharUp.) The second argument is a
                pointer to a font definition structure; five fonts are
                provided with gd, gdFontTiny, gdFontSmall,
                gdFontMediumBold, gdFontLarge, and gdFontGiant. You must
                include the files "gdfontt.h", "gdfonts.h", "gdfontmb.h",
                "gdfontl.h" and "gdfontg.h" respectively and (if you are
                not using a library-based approach) link with the
                corresponding .c files to use the provided fonts.The
                null-terminated C string specified by the fifth argument
                is drawn from bottom to top (rotated 90 degrees) in the
                specified color. (See gdImageString for a way of drawing
                horizontal text.) Pixels not set by a particular
                character retain their previous color.
                

#include "gd.h"
#include "gdfontl.h"
#include <string.h>
... inside a function ...
gdImagePtr im;
int black;
int white;
/* String to draw. */
char *s = "Hello.";
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color white (red, green and blue all maximum). */
white = gdImageColorAllocate(im, 255, 255, 255);
/* Draw a centered string going upwards. Axes are reversed,
        and Y axis is decreasing as the string is drawn. */
gdImageStringUp(im, gdFontLarge,
        im->w / 2 - gdFontLarge->h / 2,
        im->h / 2 + (strlen(s) * gdFontLarge->w / 2),
        s, white);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

        void gdImageStringUp16(gdImagePtr im, gdFontPtr font, int x, int
                y, unsigned short *s, int color) (FUNCTION)
                gdImageString is used to draw multiple 16-bit characters
                vertically on the image. (To draw single characters, use
                gdImageChar.) The second argument is a pointer to a font
                definition structure; five fonts are provided with gd,
                gdFontTiny, gdFontSmall, gdFontMediumBold, gdFontLarge,
                and gdFontGiant. You must include the files "gdfontt.h",
                "gdfonts.h", "gdfontmb.h", "gdfontl.h" and "gdfontg.h"
                respectively and (if you are not using a library-based
                approach) link with the corresponding .c files to use the
                provided fonts. The null-terminated string of characters
                represented as 16-bit unsigned short integers specified
                by the fifth argument is drawn from bottom to top in the
                specified color. (See gdImageStringUp16 for a way of
                drawing horizontal text.) Pixels not set by a particular
                character retain their previous color.
                
                This function was added in gd1.3 to provide a means of
                rendering fonts with more than 256 characters for those
                who have them. A more frequently used routine is
                gdImageStringUp.
                
  Color-handling functions
  
        int gdImageColorAllocate(gdImagePtr im, int r, int g, int b)
                (FUNCTION)
                gdImageColorAllocate finds the first available color
                index in the image specified, sets its RGB values to
                those requested (255 is the maximum for each), and
                returns the index of the new color table entry. When
                creating a new image, the first time you invoke this
                function, you are setting the background color for that
                image.
                
                In the event that all gdMaxColors colors (256) have
                already been allocated, gdImageColorAllocate will return
                -1 to indicate failure. (This is not uncommon when
                working with existing GIF files that already use 256
                colors.) Note that gdImageColorAllocate does not check
                for existing colors that match your request; see
                gdImageColorExact and gdImageColorClosest for ways to
                locate existing colors that approximate the color desired
                in situations where a new color is not available.
                

... inside a function ...
gdImagePtr im;
int black;
int red;
im = gdImageCreate(100, 100);
/* Background color (first allocated) */
black = gdImageColorAllocate(im, 0, 0, 0);
/* Allocate the color red. */
red = gdImageColorAllocate(im, 255, 0, 0);
/* Draw a dashed line from the upper left corner to the lower right corner. */
gdImageDashedLine(im, 0, 0, 99, 99, red);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

        int gdImageColorClosest(gdImagePtr im, int r, int g, int b)
                (FUNCTION)
                gdImageColorClosest searches the colors which have been
                defined thus far in the image specified and returns the
                index of the color with RGB values closest to those of
                the request. (Closeness is determined by Euclidian
                distance, which is used to determine the distance in
                three-dimensional color space between colors.)
                
                If no colors have yet been allocated in the image,
                gdImageColorClosest returns -1.
                
                This function is most useful as a backup method for
                choosing a drawing color when an image already contains
                gdMaxColors (256) colors and no more can be allocated.
                (This is not uncommon when working with existing GIF
                files that already use many colors.) See
                gdImageColorExact for a method of locating exact matches
                only.
                

... inside a function ...
gdImagePtr im;
FILE *in;
int red;
/* Let's suppose that photo.gif is a scanned photograph with
        many colors. */
in = fopen("photo.gif", "rb");
im = gdImageCreateFromGif(in);
fclose(in);
/* Try to allocate red directly */
red = gdImageColorAllocate(im, 255, 0, 0);
/* If we fail to allocate red... */
if (red == (-1)) {
        /* Find the closest color instead. */
        red = gdImageColorClosest(im, 255, 0, 0);
}
/* Draw a dashed line from the upper left corner to the lower right corner */
gdImageDashedLine(im, 0, 0, 99, 99, red);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

        int gdImageColorExact(gdImagePtr im, int r, int g, int b)
                (FUNCTION)
                gdImageColorExact searches the colors which have been
                defined thus far in the image specified and returns the
                index of the first color with RGB values which exactly
                match those of the request. If no allocated color matches
                the request precisely, gdImageColorExact returns -1. See
                gdImageColorClosest for a way to find the color closest
                to the color requested.
                

... inside a function ...
gdImagePtr im;
int red;
in = fopen("photo.gif", "rb");
im = gdImageCreateFromGif(in);
fclose(in);
/* The image may already contain red; if it does, we'll save a slot
        in the color table by using that color. */
/* Try to allocate red directly */
red = gdImageColorExact(im, 255, 0, 0);
/* If red isn't already present... */
if (red == (-1)) {
        /* Second best: try to allocate it directly. */
        red = gdImageColorAllocate(im, 255, 0, 0);
        /* Out of colors, so find the closest color instead. */
        red = gdImageColorClosest(im, 255, 0, 0);
}
/* Draw a dashed line from the upper left corner to the lower right corner */
gdImageDashedLine(im, 0, 0, 99, 99, red);
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

        int gdImageColorsTotal(gdImagePtr im) (MACRO)
                gdImageColorsTotal is a macro which returns the number of
                colors currently allocated in the image. Use this macro
                to obtain this information; do not access the structure
                directly.
                
        int gdImageColorRed(gdImagePtr im, int c) (MACRO)
                gdImageColorRed is a macro which returns the red portion
                of the specified color in the image. Use this macro to
                obtain this information; do not access the structure
                directly.
                
        int gdImageColorGreen(gdImagePtr im, int c) (MACRO)
                gdImageColorGreen is a macro which returns the green
                portion of the specified color in the image. Use this
                macro to obtain this information; do not access the
                structure directly.
                
        int gdImageColorBlue(gdImagePtr im, int c) (MACRO)
                gdImageColorBlue is a macro which returns the green
                portion of the specified color in the image. Use this
                macro to obtain this information; do not access the
                structure directly.
                
        int gdImageGetInterlaced(gdImagePtr im) (MACRO)
                gdImageGetInterlaced is a macro which returns true (1) if
                the image is interlaced, false (0) if not. Use this macro
                to obtain this information; do not access the structure
                directly. See gdImageInterlace for a means of interlacing
                images.
                
        int gdImageGetTransparent(gdImagePtr im) (MACRO)
                gdImageGetTransparent is a macro which returns the
                current transparent color index in the image. If there is
                no transparent color, gdImageGetTransparent returns -1.
                Use this macro to obtain this information; do not access
                the structure directly.
                
        void gdImageColorDeallocate(gdImagePtr im, int color) (FUNCTION)
                gdImageColorDeallocate marks the specified color as being
                available for reuse. It does not attempt to determine
                whether the color index is still in use in the image.
                After a call to this function, the next call to
                gdImageColorAllocate for the same image will set new RGB
                values for that color index, changing the color of any
                pixels which have that index as a result. If multiple
                calls to gdImageColorDeallocate are made consecutively,
                the lowest-numbered index among them will be reused by
                the next gdImageColorAllocate call.
                

... inside a function ...
gdImagePtr im;
int red, blue;
in = fopen("photo.gif", "rb");
im = gdImageCreateFromGif(in);
fclose(in);
/* Look for red in the color table. */
red = gdImageColorExact(im, 255, 0, 0);
/* If red is present... */
if (red != (-1)) {
        /* Deallocate it. */
        gdImageColorDeallocate(im, red);
        /* Allocate blue, reusing slot in table.
                Existing red pixels will change color. */
        blue = gdImageColorAllocate(im, 0, 0, 255);
}
/* ... Do something with the image, such as saving it to a file... */
/* Destroy it */
gdImageDestroy(im);

        void gdImageColorTransparent(gdImagePtr im, int color) (FUNCTION)
                
                gdImageColorTransparent sets the transparent color index
                for the specified image to the specified index. To
                indicate that there should be no transparent color,
                invoke gdImageColorTransparent with a color index of -1.
                
                The color index used should be an index allocated by
                gdImageColorAllocate, whether explicitly invoked by your
                code or implicitly invoked by loading an image. In order
                to ensure that your image has a reasonable appearance
                when viewed by users who do not have transparent
                background capabilities, be sure to give reasonable RGB
                values to the color you allocate for use as a transparent
                color, even though it will be transparent on systems that
                support transparency.
                

... inside a function ...
gdImagePtr im;
int black;
FILE *in, *out;
in = fopen("photo.gif", "rb");
im = gdImageCreateFromGif(in);
fclose(in);
/* Look for black in the color table and make it transparent. */
black = gdImageColorExact(im, 0, 0, 0);
/* If black is present... */
if (black != (-1)) {
        /* Make it transparent */
        gdImageColorTransparent(im, black);
}
/* Save the newly-transparent image back to the file */
out = fopen("photo.gif", "wb");
gdImageGif(im, out);
fclose(out);
/* Destroy it */
gdImageDestroy(im);

  Copying and resizing functions
  
        void gdImageCopy(gdImagePtr dst, gdImagePtr src, int dstX, int
                dstY, int srcX, int srcY, int w, int h) (FUNCTION)
                gdImageCopy is used to copy a rectangular portion of one
                image to another image. (For a way of stretching or
                shrinking the image in the process, see
                gdImageCopyResized.)
                
                The dst argument is the destination image to which the
                region will be copied. The src argument is the source
                image from which the region is copied. The dstX and dstY
                arguments specify the point in the destination image to
                which the region will be copied. The srcX and srcY
                arguments specify the upper left corner of the region in
                the source image. The w and h arguments specify the width
                and height of the region.
                
                When you copy a region from one location in an image to
                another location in the same image, gdImageCopy will
                perform as expected unless the regions overlap, in which
                case the result is unpredictable.
                
                Important note on copying between images: since different
                images do not necessarily have the same color tables,
                pixels are not simply set to the same color index values
                to copy them. gdImageCopy will attempt to find an
                identical RGB value in the destination image for each
                pixel in the copied portion of the source image by
                invoking gdImageColorExact. If such a value is not found,
                gdImageCopy will attempt to allocate colors as needed
                using gdImageColorAllocate. If both of these methods
                fail, gdImageCopy will invoke gdImageColorClosest to find
                the color in the destination image which most closely
                approximates the color of the pixel being copied.
                

... Inside a function ...
gdImagePtr im_in;
gdImagePtr im_out;
int x, y;
FILE *in;
FILE *out;
/* Load a small gif to tile the larger one with */
in = fopen("small.gif", "rb");
im_in = gdImageCreateFromGif(in);
fclose(in);
/* Make the output image four times as large on both axes */
im_out = gdImageCreate(im_in->sx * 4, im_in->sy * 4);
/* Now tile the larger image using the smaller one */
for (y = 0; (y < 4); y++) {
        for (x = 0; (x < 4); x++) {
                gdImageCopy(im_out, im_in,
                        x * im_in->sx, y * im_in->sy,
                        0, 0,
                        im_in->sx, im_in->sy);
        }
}
out = fopen("tiled.gif", "wb");
gdImageGif(im_out, out);
fclose(out);
gdImageDestroy(im_in);
gdImageDestroy(im_out);

        void gdImageCopyResized(gdImagePtr dst, gdImagePtr src, int dstX,
                int dstY, int srcX, int srcY, int destW, int destH, int
                srcW, int srcH) (FUNCTION)
                gdImageCopyResized is used to copy a rectangular portion
                of one image to another image. The X and Y dimensions of
                the original region and the destination region can vary,
                resulting in stretching or shrinking of the region as
                appropriate. (For a simpler version of this function
                which does not deal with resizing, see gdImageCopy.)
                
                The dst argument is the destination image to which the
                region will be copied. The src argument is the source
                image from which the region is copied. The dstX and dstY
                arguments specify the point in the destination image to
                which the region will be copied. The srcX and srcY
                arguments specify the upper left corner of the region in
                the source image. The dstW and dstH arguments specify the
                width and height of the destination region. The srcW and
                srcH arguments specify the width and height of the source
                region and can differ from the destination size, allowing
                a region to be scaled during the copying process.
                
                When you copy a region from one location in an image to
                another location in the same image, gdImageCopy will
                perform as expected unless the regions overlap, in which
                case the result is unpredictable. If this presents a
                problem, create a scratch image in which to keep
                intermediate results.
                
                Important note on copying between images: since images do
                not necessarily have the same color tables, pixels are
                not simply set to the same color index values to copy
                them. gdImageCopy will attempt to find an identical RGB
                value in the destination image for each pixel in the
                copied portion of the source image by invoking
                gdImageColorExact. If such a value is not found,
                gdImageCopy will attempt to allocate colors as needed
                using gdImageColorAllocate. If both of these methods
                fail, gdImageCopy will invoke gdImageColorClosest to find
                the color in the destination image which most closely
                approximates the color of the pixel being copied.
                

... Inside a function ...
gdImagePtr im_in;
gdImagePtr im_out;
int x, y;
FILE *in;
FILE *out;
/* Load a small gif to expand in the larger one */
in = fopen("small.gif", "rb");
im_in = gdImageCreateFromGif(in);
fclose(in);
/* Make the output image four times as large on both axes */
im_out = gdImageCreate(im_in->sx * 4, im_in->sy * 4);
/* Now copy the smaller image, but four times larger */
gdImageCopyResized(im_out, im_in, 0, 0, 0, 0,
        im_out->sx, im_out->sy,
        im_in->sx, im_in->sy);
out = fopen("large.gif", "wb");
gdImageGif(im_out, out);
fclose(out);
gdImageDestroy(im_in);
gdImageDestroy(im_out);

  Miscellaneous Functions
  
              gdImageInterlace(gdImagePtr im, int interlace) (FUNCTION)
                      gdImageInterlace is used to determine whether an
                      image should be stored in a linear fashion, in
                      which lines will appear on the display from first
                      to last, or in an interlaced fashion, in which the
                      image will "fade in" over several passes. By
                      default, images are not interlaced.
                      
                      A nonzero value for the interlace argument turns on
                      interlace; a zero value turns it off. Note that
                      interlace has no effect on other functions, and has
                      no meaning unless you save the image in GIF format;
                      the gd and xbm formats do not support interlace.
                      
                      When a GIF is loaded with gdImageCreateFromGif ,
                      interlace will be set according to the setting in
                      the GIF file.
                      
                      Note that many GIF viewers and web browsers do not
                      support interlace. However, the interlaced GIF
                      should still display; it will simply appear all at
                      once, just as other images do.
                      

gdImagePtr im;
FILE *out;
/* ... Create or load the image... */

/* Now turn on interlace */
gdImageInterlace(im, 1);
/* And open an output file */
out = fopen("test.gif", "wb");
/* And save the image */
gdImageGif(im, out);
fclose(out);
gdImageDestroy(im);

  Constants
  
              gdBrushed (CONSTANT)
                      Used in place of a color when invoking a
                      line-drawing function such as gdImageLine or
                      gdImageRectangle. When gdBrushed is used as the
                      color, the brush image set with gdImageSetBrush is
                      drawn in place of each pixel of the line (the brush
                      is usually larger than one pixel, creating the
                      effect of a wide paintbrush). See also
                      gdStyledBrushed for a way to draw broken lines with
                      a series of distinct copies of an image.
                      
              gdMaxColors(CONSTANT)
                      The constant 256. This is the maximum number of
                      colors in a GIF file according to the GIF standard,
                      and is also the maximum number of colors in a gd
                      image.
                      
              gdStyled (CONSTANT)
                      Used in place of a color when invoking a
                      line-drawing function such as gdImageLine or
                      gdImageRectangle. When gdStyled is used as the
                      color, the colors of the pixels are drawn
                      successively from the style that has been set with
                      gdImageSetStyle. If the color of a pixel is equal
                      to gdTransparent, that pixel is not altered. (This
                      mechanism is completely unrelated to the
                      "transparent color" of the image itself; see
                      gdImageColorTransparent gdImageColorTransparent for
                      that mechanism.) See also gdStyledBrushed.
                      
              gdStyledBrushed (CONSTANT)
                      Used in place of a color when invoking a
                      line-drawing function such as gdImageLine or
                      gdImageRectangle. When gdStyledBrushed is used as
                      the color, the brush image set with gdImageSetBrush
                      is drawn at each pixel of the line, providing that
                      the style set with gdImageSetStyle contains a
                      nonzero value (OR gdTransparent, which does not
                      equal zero but is supported for consistency) for
                      the current pixel. (Pixels are drawn successively
                      from the style as the line is drawn, returning to
                      the beginning when the available pixels in the
                      style are exhausted.) Note that this differs from
                      the behavior of gdStyled, in which the values in
                      the style are used as actual pixel colors, except
                      for gdTransparent.
                      
              gdDashSize (CONSTANT)
                      The length of a dash in a dashed line. Defined to
                      be 4 for backwards compatibility with programs that
                      use gdImageDashedLine. New programs should use
                      gdImageSetStyle and call the standard gdImageLine
                      function with the special "color" gdStyled or
                      gdStyledBrushed.
                      
              gdTiled (CONSTANT)
                      Used in place of a normal color in
                      gdImageFilledRectangle, gdImageFilledPolygon,
                      gdImageFill, and gdImageFillToBorder. gdTiled
                      selects a pixel from the tile image set with
                      gdImageSetTile in such a way as to ensure that the
                      filled area will be tiled with copies of the tile
                      image. See the discussions of gdImageFill and
                      gdImageFillToBorder for special restrictions
                      regarding those functions.
                      
              gdTransparent (CONSTANT)
                      Used in place of a normal color in a style to be
                      set with gdImageSetStyle. gdTransparent is not the
                      transparent color index of the image; for that
                      functionality please see gdImageColorTransparent.
                      
  About the additional .gd image file format
  
                      In addition to reading and writing the GIF format
                      and reading the X Bitmap format, gd has the
                      capability to read and write its own ".gd" format.
                      This format is not intended for general purpose use
                      and should never be used to distribute images. It
                      is not a compressed format. Its purpose is solely
                      to allow very fast loading of images your program
                      needs often in order to build other images for
                      output. If you are experiencing performance
                      problems when loading large, fixed GIF images your
                      program needs to produce its output images, you may
                      wish to examine the functions gdImageCreateFromGd
                      and gdImageGd, which read and write .gd format
                      images.
                      
                      The program "giftogd.c" is provided as a simple way
                      of converting .gif files to .gd format. I emphasize
                      again that you will not need to use this format
                      unless you have a need for high-speed loading of a
                      few frequently-used images in your program.
                      
  Please tell us you're using gd!
  
                      When you contact us and let us know you are using
                      gd, you help us justify the time spent in
                      maintaining and improving it. So please let us
                      know. If the results are publicly visible on the
                      web, a URL is a wonderful thing to receive, but if
                      it's not a publicly visible project, a simple note
                      is just as welcome.
                      
  If you have problems
  
                      If you have any difficulties with gd, feel free to
                      contact the author, Thomas Boutell. Be sure to read
                      this manual carefully first.
                      
  Alphabetical quick index
  
                      gdBrushed | gdDashSize | gdFont | gdFontPtr |
                      gdImage | gdImageArc | gdImageBlue |
                      gdImageBoundsSafe | gdImageChar | gdImageCharUp |
                      gdImageColorAllocate | gdImageColorClosest |
                      gdImageColorDeallocate | gdImageColorExact |
                      gdImageColorTransparent | gdImageCopy |
                      gdImageCopyResized | gdImageCreate |
                      gdImageCreateFromGd | gdImageCreateFromGif |
                      gdImageCreateFromXbm | gdImageDashedLine |
                      gdImageDestroy | gdImageFill | gdImageFillToBorder
                      | gdImageFilledRectangle | gdImageGd |
                      gdImageGetInterlaced | gdImageGetPixel |
                      gdImageGetTransparent | gdImageGif | gdImageGreen |
                      gdImageInterlace | gdImageLine |
                      gdImageFilledPolygon | gdImagePolygon | gdImagePtr
                      | gdImageRectangle | gdImageRed | gdImageSetBrush |
                      gdImageSetPixel | gdImageSetStyle | gdImageSetTile
                      | gdImageString | gdImageString16 | gdImageStringUp
                      | gdImageStringUp16 | gdMaxColors | gdPoint |
                      gdStyled | gdStyledBrushed | gdTiled |
                      gdTransparent
                      
                      Boutell.Com, Inc.
