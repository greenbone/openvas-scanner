/* GDCHART 0.94b  PIE CHART SAMPLE  12 Nov 1998 */

/* creates a file "pie.gif".  Can be stdout for CGI use. */
/*  vi: :set tabstop=4 */

#include <includes.h>
#include "math.h"
#include "gdc.h"
#include "gdcpie.h"

main( int argc, char *argv[] )
{
	/* labels */
	char		*lbl[] = { "CPQ\n(DEC)",
						   "HP",
						   "SCO",
						   "IBM",
						   "SGI",
						   "SUN\nSPARC",
						   "other" }; 
	/* values to chart */
	float		 p[] = { 12.5,
						 20.1,
						 2.0,
						 22.0,
						 5.0,
						 18.0,
						 13.0 };

	FILE		*fp = fopen( "pie.gif", "wb" );

	/* set which slices to explode, and by how much */
	int				expl[] = { 0, 0, 0, 0, 0, 20, 0 };

	/* set missing slices */
	unsigned char	missing[] = { FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, TRUE };

	/* colors */
	unsigned long	clr[] = { 0xFF4040L, 0x80FF80L, 0x8080FFL, 0xFF80FFL, 0xFFFF80L, 0x80FFFFL, 0x0080FFL };

	/* set options  */
	/* a lot of options are set here for illustration */
	/* none need be - see gdcpie.h for defaults */
	GDCPIE_title = "Sample\nPIE";
	GDCPIE_label_line = TRUE;
	GDCPIE_label_dist = 15;				/* dist. labels to slice edge */
										/* can be negative */
	GDCPIE_LineColor = 0x000000L;
	GDCPIE_label_size = GDC_SMALL;
/*	GDCPIE_3d_depth  = 25;	*/
/*	GDCPIE_3d_angle  = 45;				   0 - 359 */
	GDCPIE_explode   = expl;			/* default: NULL - no explosion */
	GDCPIE_Color     = clr;
	GDCPIE_BGColor   = 0xFFFFFFL;
	GDCPIE_EdgeColor = 0x000000L;		/* default is GDCPIE_NOCOLOR */
										/* for no edging */
	GDCPIE_missing   = missing;			/* default: NULL - none missing */

										/* add percentage to slice label */
										/* below the slice label */
	GDCPIE_percent_labels = GDCPIE_PCT_RIGHT;

	/* call the lib */
	pie_gif( 480,			/* width */
			 360,			/* height */
			 fp,			/* open file pointer */
			 GDC_3DPIE,		/* or GDC_2DPIE */
			 7,				/* number of slices */
			 lbl,			/* slice labels (unlike out_gif(), can be NULL */
			 p );			/* data array */

	fclose( fp );
	exit( 0 );
}
