/* GDCHART 0.94b  GDCHART.H  12 Nov 1998 */

#ifndef _GDCHART_H
#define _GDCHART_H

#ifndef _GDC_H
#include "gdc.h"
#endif

#ifdef HAVE_FLOAT_H
#include <float.h>
#endif

#ifndef MAXFLOAT
# define MAXFLOAT FLT_MAX
#endif

#define MAX_NOTE_LEN		19

typedef enum {
			 GDC_LINE,
			 GDC_AREA,
			 GDC_BAR,
			 GDC_HILOCLOSE,
			 GDC_COMBO_LINE_BAR,			/* aka, VOL[ume] */
			 GDC_COMBO_HLC_BAR,
			 GDC_COMBO_LINE_AREA,
			 GDC_COMBO_HLC_AREA,
			 GDC_3DHILOCLOSE,
			 GDC_3DCOMBO_LINE_BAR,
			 GDC_3DCOMBO_LINE_AREA,
			 GDC_3DCOMBO_HLC_BAR,
			 GDC_3DCOMBO_HLC_AREA,
			 GDC_3DBAR,
			 GDC_3DAREA,
			 GDC_3DLINE
			 } GDC_CHART_T;

typedef enum {
			 GDC_STACK_DEPTH,				/* "behind" (even non-3D) */
			 GDC_STACK_SUM,
			 GDC_STACK_BESIDE,
			 GDC_STACK_LAYER
			 } GDC_STACK_T;					/* applies only to num_lines > 1 */

typedef enum {
			 GDC_HLC_DIAMOND         = 1,
			 GDC_HLC_CLOSE_CONNECTED = 2,	/* can't be used w/ CONNECTING */
			 GDC_HLC_CONNECTING      = 4,	/* can't be used w/ CLOSE_CONNECTED */
			 GDC_HLC_I_CAP           = 8
			 } GDC_HLC_STYLE_T;				/* can be OR'd */

											/* only 1 annotation allowed */
typedef struct
			{
			float			point;			/* 0 <= point < num_points */
			unsigned long	color;
			char			note[MAX_NOTE_LEN+1];	/* NLs ok here */
			} GDC_ANNOTATION_T;

typedef enum {
			 GDC_SCATTER_TRIANGLE_DOWN,
			 GDC_SCATTER_TRIANGLE_UP
			 } GDC_SCATTER_IND_T;
typedef struct
			{
			float				point;		/* 0 <= point < num_points */
			float				val;
			unsigned short		width;		/* % (1-100) */
			unsigned long		color;
			GDC_SCATTER_IND_T	ind;
			} GDC_SCATTER_T;

/****************************************************/
/********** USER CHART OPTIONS w/ defaults **********/
/****************************************************/
EXTERND char				*GDC_ytitle;
EXTERND char				*GDC_xtitle;
EXTERND char				*GDC_ytitle2;		/* ostesibly: volume label */
EXTERND char				*GDC_title;			/* NLs ok here */
EXTERND enum GDC_font_size	GDC_title_size		DEFAULTO( GDC_MEDBOLD );
EXTERND enum GDC_font_size	GDC_ytitle_size		DEFAULTO( GDC_MEDBOLD );
EXTERND enum GDC_font_size	GDC_xtitle_size		DEFAULTO( GDC_MEDBOLD );
EXTERND enum GDC_font_size	GDC_yaxisfont_size	DEFAULTO( GDC_SMALL );
EXTERND enum GDC_font_size	GDC_xaxisfont_size	DEFAULTO( GDC_SMALL );
EXTERND char				*GDC_ylabel_fmt		DEFAULTO( NULL );		/* printf fmt'ing, e.g.: "%.2f" */
EXTERND char				*GDC_ylabel2_fmt	DEFAULTO( NULL );		/* default: "%.0f" future: fractions */
EXTERND short				GDC_xlabel_spacing	DEFAULTO( 5 );			/* pixels  MAXSHORT means force all */
EXTERND char				GDC_ylabel_density	DEFAULTO( 80 );			/* % */
EXTERND float				GDC_requested_ymin	DEFAULTO( GDC_NOVALUE );
EXTERND float				GDC_requested_ymax	DEFAULTO( GDC_NOVALUE );
EXTERND float				GDC_requested_yinterval	DEFAULTO( GDC_NOVALUE );
EXTERND char				GDC_0Shelf			DEFAULTO( TRUE );		/* if applicable */
EXTERND char				GDC_grid			DEFAULTO( TRUE );
EXTERND char				GDC_xaxis			DEFAULTO( TRUE );
EXTERND char				GDC_yaxis			DEFAULTO( TRUE );
EXTERND char				GDC_yaxis2			DEFAULTO( TRUE );
EXTERND char				GDC_yval_style		DEFAULTO( TRUE );
EXTERND GDC_STACK_T			GDC_stack_type		DEFAULTO( GDC_STACK_DEPTH );
EXTERND float				GDC_3d_depth		DEFAULTO( 5.0 );		/* % gif size */
EXTERND unsigned char		GDC_3d_angle		DEFAULTO( 45 );			/* 1-89 */
EXTERND unsigned char		GDC_bar_width		DEFAULTO( 75 );			/* % (1-100) */
EXTERND GDC_HLC_STYLE_T		GDC_HLC_style		DEFAULTO( GDC_HLC_CLOSE_CONNECTED );
EXTERND unsigned char		GDC_HLC_cap_width	DEFAULTO( 25 );			/* % (1-100) */
EXTERND GDC_ANNOTATION_T	*GDC_annotation		DEFAULTO( (GDC_ANNOTATION_T*)NULL );
EXTERND enum GDC_font_size	GDC_annotation_font	DEFAULTO( GDC_SMALL );
EXTERND int					GDC_num_scatter_pts	DEFAULTO( 0 );
EXTERND GDC_SCATTER_T		*GDC_scatter		DEFAULTO( (GDC_SCATTER_T*)NULL );
EXTERND char				GDC_thumbnail		DEFAULTO( FALSE );
EXTERND char				*GDC_thumblabel;
EXTERND float				GDC_thumbval		DEFAULTO( -MAXFLOAT );
EXTERND char				GDC_border			DEFAULTO( TRUE );
EXTERND unsigned long		GDC_BGColor			DEFAULTO( 0x000000L );	 /* black */
EXTERND unsigned long		GDC_GridColor		DEFAULTO( 0xA0A0A0L );	 /* gray */
EXTERND unsigned long		GDC_LineColor		DEFAULTO( GDC_DFLTCOLOR );
EXTERND unsigned long		GDC_PlotColor		DEFAULTO( GDC_DFLTCOLOR );
EXTERND unsigned long		GDC_VolColor		DEFAULTO( 0xA0A0FFL );	 /* lgtblue1 */
EXTERND unsigned long		GDC_TitleColor		DEFAULTO( GDC_DFLTCOLOR ); /* "opposite" of BG */
EXTERND unsigned long		GDC_XTitleColor		DEFAULTO( GDC_DFLTCOLOR );
EXTERND unsigned long		GDC_YTitleColor		DEFAULTO( GDC_DFLTCOLOR );
EXTERND unsigned long		GDC_YTitle2Color	DEFAULTO( GDC_DFLTCOLOR );
EXTERND unsigned long		GDC_XLabelColor		DEFAULTO( GDC_DFLTCOLOR );
EXTERND unsigned long		GDC_YLabelColor		DEFAULTO( GDC_DFLTCOLOR );
EXTERND unsigned long		GDC_YLabel2Color	DEFAULTO( GDC_DFLTCOLOR );
							/* supercedes VolColor	ulong_color[num_points] */
EXTERND unsigned long		*GDC_ExtVolColor	DEFAULTO( (unsigned long*)NULL );
							/* supercedes LineColor	ulong_color[num_sets] */
EXTERND unsigned long		*GDC_SetColor		DEFAULTO( (unsigned long*)NULL );
							/* supercedes SetColor	ulong_color[num_sets][num_points] */
EXTERND unsigned long		*GDC_ExtColor		DEFAULTO( (unsigned long*)NULL );
EXTERND char				GDC_transparent_bg	DEFAULTO( FALSE );
EXTERND char				*GDC_BGImage		DEFAULTO( (char*)NULL );
/* legends?  separate gif? */
/* auto-size fonts, based on GIF size? */

/* ----- following options are for expert users only ----- */
												/* for alignment of multiple charts */
												/* USE WITH CAUTION! */
EXTERND char				GDC_hard_size		DEFAULTO( FALSE );
EXTERND int					GDC_hard_xorig		DEFAULTO( 0 );				/* in/out */
EXTERND int					GDC_hard_graphwidth	DEFAULTO( 0 );				/* in/out */
EXTERND int					GDC_hard_yorig		DEFAULTO( 0 );				/* in/out */
EXTERND int					GDC_hard_grapheight	DEFAULTO( 0 );				/* in/out */

/**** COMMON OPTIONS ********************************/
/* NOTE:  common options copy here for reference only! */
/*        they live in gdc.h                           */
#ifndef _GDC_COMMON_OPTIONS
#define _GDC_COMMON_OPTIONS
EXTERND char				GDC_generate_gif	DEFAULTO( TRUE );

EXTERND GDC_HOLD_IMAGE_T	GDC_hold_img		DEFAULTO( GDC_DESTROY_IMAGE );
EXTERND void				*GDC_image			DEFAULTO( (void*)NULL );	/* in/out */
#endif
/****************************************************/

#ifdef GDC_LIB
#define clrallocate( im, rawclr )		_clrallocate( im, rawclr, GDC_BGColor )
#define clrshdallocate( im, rawclr )	_clrshdallocate( im, rawclr, GDC_BGColor )
#endif

int GDC_out_graph( short		gifwidth,
				   short		gifheight,  
				   FILE			*gif_fptr,		/* open file pointer (gif out) */
				   GDC_CHART_T	type,
				   int			num_points,		/* points along x axis (even iterval) */
				   char			*xlbl[],
				   int			num_sets,
								... );
/* expected params (...) for each chart type:
GDC_LINE
GDC_BAR
GDC_3DBAR
GDC_3DAREA
GDC_AREA			float	vals[], ...
												multiple sets make sense for rest?
GDC_HILOCLOSE		float	high[],
					float	low[],
					float	close[]

GDC_COMBO_LINE_BAR
GDC_COMBO_LINE_AREA	float	val[],
					float   vol[]

GDC_COMBO_HLC_BAR
GDC_COMBO_HLC_AREA	float   high[],
                    float   low[],
                    float   close[],
					float   vol[]

*/

/* Notes:
	GDC_thumbnail = TRUE
	is equivelent to:	GDC_grid = FALSE
						GDC_xaxis = FALSE
						GDC_yaxis = FALSE
*/

#endif /*!_GDCHART_H*/
