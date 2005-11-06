/* GDCHART 0.94b  GDCPIE.H  12 Nov 1998 */

#ifndef _GDCPIE_H
#define _GDCPIE_H

#ifndef _GDC_H
#include "gdc.h"
#endif

#ifdef GDC_LIB
extern struct GDC_FONT_T	GDC_fontc[];
#endif

typedef enum {
             GDC_3DPIE,
             GDC_2DPIE
             } GDCPIE_TYPE;

typedef enum {
             GDCPIE_PCT_NONE,
             GDCPIE_PCT_ABOVE,		/* relative to label, if any */
             GDCPIE_PCT_BELOW,
             GDCPIE_PCT_RIGHT,
             GDCPIE_PCT_LEFT
             } GDCPIE_PCT_TYPE;


/**************************************************/
/**** USER DEFINABLE PIE OPTIONS  w/ defaults *****/
/**************************************************/
EXTERND unsigned long		GDCPIE_BGColor			DEFAULTO( 0x000000L );	/* black */
EXTERND unsigned long		GDCPIE_PlotColor		DEFAULTO( 0xC0C0C0L );	/* gray */
EXTERND unsigned long		GDCPIE_LineColor		DEFAULTO( GDC_DFLTCOLOR );
EXTERND unsigned long		GDCPIE_EdgeColor		DEFAULTO( GDC_NOCOLOR ); /* edging on/off */

EXTERND char				GDCPIE_other_threshold	DEFAULTO( -1 );
EXTERND unsigned short		GDCPIE_3d_angle			DEFAULTO( 45 );			/* 0-360 */
EXTERND unsigned short		GDCPIE_3d_depth			DEFAULTO( 10 );			/* % gif width */
EXTERND char				*GDCPIE_title			DEFAULTO( NULL );		/* NLs ok here */
EXTERND enum GDC_font_size	GDCPIE_title_size		DEFAULTO( GDC_MEDBOLD );
EXTERND enum GDC_font_size	GDCPIE_label_size		DEFAULTO( GDC_SMALL );
EXTERND int					GDCPIE_label_dist		DEFAULTO( 1+8/2 );		/* 1+GDC_fontc[GDCPIE_label_size].h/2 */
EXTERND unsigned char		GDCPIE_label_line		DEFAULTO( FALSE );		/* from label to slice */

EXTERND int					*GDCPIE_explode			DEFAULTO( (int*)NULL );	/* [num_points] */
															/* [num_points] supercedes GDCPIE_PlotColor */
EXTERND unsigned long		*GDCPIE_Color			DEFAULTO( (unsigned long*)NULL );
EXTERND unsigned char		*GDCPIE_missing			DEFAULTO( (unsigned char*)NULL );	/* TRUE/FALSE */

EXTERND GDCPIE_PCT_TYPE		GDCPIE_percent_labels	DEFAULTO( GDCPIE_PCT_NONE );
/**** COMMON OPTIONS ******************************/
/* NOTE:  common options copy here for reference only! */
/*        they live in gdc.h                           */
#ifndef _GDC_COMMON_OPTIONS
#define _GDC_COMMON_OPTIONS
EXTERND char				GDC_generate_gif	DEFAULTO( TRUE );

EXTERND GDC_HOLD_IMAGE_T	GDC_hold_img		DEFAULTO( GDC_DESTROY_IMAGE );
EXTERND void				*GDC_image			DEFAULTO( (void*)NULL );	/* in/out */
#endif
/**************************************************/

#ifdef GDC_LIB
#define clrallocate( im, rawclr )		_clrallocate( im, rawclr, GDCPIE_BGColor )
#define clrshdallocate( im, rawclr )	_clrshdallocate( im, rawclr, GDCPIE_BGColor )
#endif

void pie_gif( short			width,
			  short			height,
			  FILE*,						/* open file pointer, can be stdout */
			  GDCPIE_TYPE,
			  int			num_points,
			  char			*labels[],		/* slice labels */
			  float			data[] );

#endif /*!_GDCPIE_H*/
