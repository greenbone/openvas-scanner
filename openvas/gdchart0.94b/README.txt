GDChart Home Page:
	http://www.fred.net/brv/chart/

Also see v0.94b notes

GDCHART v0.94b

NOTE the 'b'.  Yes, this is still in beta.

Compiles cleanly on HPUX LINUX SOLARIS SUNOS
  just type 'make' in the chart directory
  this produces: gdc.o gdchart.o, price_conv.o gdc_pie.o, and gd1.3/libgd.a
  these with gdc.h, gdchart.h, gdcpie.h, and gd1.3/*.h make up the gdchart library


  gdc_samp1.c, gdc_samp2.c and gdc_pie_samp.c are provided as examples.
  They're in the makefile for example compilation/linking
  gdc_samp1 writes to stdout, so if running from the command line:
        gdc_samp1 > test.gif


gcc 2.7 or better is required.
   (Others can't handle non-static auto arrays
    I've tried with Sun's C professional developers package,
    HP's ANSI compiler, MS VC++)
(if getting gcc is a problem (it's free), I can supply native binaries for
  HPUX (PA),
  Solaris (Sparc),
  SunOS (Sparc),
  Linux (x86),
 and *MAYBE*
  DEC Unix (Alpha),
  SCO (x86) )
Note to Win/NT users:
  GCC for Win/NT is required to compile the lib down to binaries that can be used by MS VC++, Borland, etc.


Quick usage notes (until a 'real' help/README page is written)
--------------------------------------------------------------

- there is precious little error checking
  be sure to pass correctly sized arrays AND the correct number of arguments

- IMPORTANT NOTE about parameter passing:
  GDCHART uses variable arguments (stdarg);
  the number of arguments must be accurate.
  num_sets (arg 7) determines the number of expected data arrays (args 8 - n)
  - for Hi Low Close types 3*num_sets data arrays are expected
  - for COMBO types an extra data array (last arg) is expected
  - for others num_sets data arrays are expected

  x label array (arg 6) (and all arrays passed): are expected to have
  num_points (arg 5) elements
  x label array (arg 6) is an array of pointers, not an array of
  character arrays:     char    *xlbl[ num_points ];
               NOT:     char    xlbl[ num_points ][ 4 ];

- Setting colors
  a single color can be set for all plotted data: GDC_PlotColor
  a separate color can be set for each SET of data: GDC_SetColor
    pointer to an array of num_sets is expected
  a separate color can be set for each plot point: GDC_ExtColor
    pointer to an array of num_sets x num_points is expected

  Note: a maximum of 256 colors is allowed.
  Also: if too many colors or 'off' colors are used,
        viewers (e.g., browsers) will render them with varying results
         (mosaic and xv seem to do the best job, MS IE seems to do the worst)


Known Problems 
--------------
  - Slice labels can overwite each other, if slices are relatively small.
    (Most PIE generating software has this exact problem.  The two most
     used 95/NT charting packages do.)
  - Stacked 3D charts plotting negative values
    (most charting packages can't handle this.)
  - If Y labels are displayed as fractions,
    precision greater than 1/256 is not possible.
  - Y label values aren't scaled - can handle ~1/64 &#60;= X &#60;= ~10,000,000
     Any potential y-label value can be set
     in gdchart.c in the 'y labels intervals' section
      add/delete/change elements in the ypoints[] array
      (be sure values are in ascending order)
     A specific interval can be forced by setting
        ylbl_interval;
    GDC_requested_y options address most of these problems
    Scaling of values may be an option in a future release.
  - Lib is not thread safe. Could easily be made so, if really needed. 
    This is due mainly to the use of the global options.
  - Scaling and centering of background images may be off, when
    the image is of a different size than the chart gif
  - under some circumstances charts with less than 3 plot points may
    not be scaled correctly


COPYRIGHT NOTICES:
+-----------------------------------------------------------------------
| GDChart is free for use in your applications and for chart generation.
| YOU MAY NOT re-distribute or represent the code as your own.
| Any re-distributions of the code MUST reference the author, and include
| any and all original documentaion.
| Copyright.  Bruce Verderaime.  1998, 1999, 2000
+-----------------------------------------------------------------------
IOW: Use it.  Don't plagiarize it!


Any bugs, questions, problems, comments please contact me
brv@fred.net
http://www.fred.net/brv/chart/


Note on GIFs:
GIF graphic format uses a copyrighted compression (LZW).  You can NOT use it without
permission from UNISYS (and IBM?).  (They want BIG $$$)

GDCHART uses gd1.3, which is supplied in its entirety.  See accompanying text.
gd1.3 does NOT use LZW.  The result is larger GIF file sizes :-(

GDCHART also works with gd1.2, which employs LZW - small GIF sizes.
If you have a LZW license, feel free to use GDCHART with gd1.2.  It's sure to be
found on the net.
If you don't have a LZW license, use gd1.2 at your own risk!
