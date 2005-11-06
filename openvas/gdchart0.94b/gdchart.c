/* GDCHART 0.94b  GDCHART.C  18 APR 1999 */
/* vi:set tabstop=4 */

#include <includes.h>
#include <limits.h>

#include <math.h>
#include <stdarg.h>

#define GDC_INCL
#define GDC_LIB
#define GDC_VARS
#include "gdc.h"
#include "gdchart.h"

#ifndef M_PI
#define M_PI   3.14159265358979323846  /* pi */
#define M_PI_2 1.57079632679489661923  /* pi/2 */
#endif

#ifdef _WIN32
#ifdef HAVE__ALLOCA
# define alloca(x) _alloca(x)
# define USE_ALLOCA
#endif /* _alloca */
#endif /* _WIN32 */

#ifdef HAVE_ALLOCA
#define USE_ALLOCA
#endif

/* two dimensional interger/float array acess */
#ifdef USE_ALLOCA
# define I(x,y)    [(x) * num_points + (y)]
#else
# define I(x,y)    [x][y] /* unix standard method */
#endif

#ifndef MAXINT
# define MAXINT INT_MAX
#endif
 

/* 
 * MkLinux defines MAXSHORT as SHORT_MAX, but does not
 * define SHORT_MAX. However, it defines a SHRT_MAX
 */
#ifndef SHORT_MAX
#ifdef SHRT_MAX
#define SHORT_MAX SHRT_MAX
#endif
#endif

#define HIGHSET		0
#define LOWSET		1
#define CLOSESET	2

/* scaled translation onto graph */
#define PX( x )		(int)( xorig + (setno*xdepth_3D) + (x)*xscl )
#define PY( y )		(int)( yorig - (setno*ydepth_3D) + (y)*yscl )
#define PV( y )		(int)( vyorig - (setno*ydepth_3D) + (y)*vyscl )

#define SET_RECT( gdp, x1, x2, y1, y2 )	gdp[0].x = gdp[3].x = x1,	\
										gdp[0].y = gdp[1].y = y1,	\
										gdp[1].x = gdp[2].x = x2,	\
										gdp[2].y = gdp[3].y = y2

#ifdef THUMB_VALS
/* -------------------------------------------------------------------
 * draw an arrow at (x,y)-upper left in arrwclr to the size of SmallFont
 * could, with just a little difficulty, be made to accept a font siz
 * ------------------------------------------------------------------- */
void
smallarrow( gdImagePtr  im,
			int			x,
			int			y,
			char		up,
			int			arrwclr )
{
	gdImageLine( im, x+2, y, x+2, y+GDC_fontc[GDC_SMALL].h, arrwclr );
	gdImageLine( im, x+3, y, x+3, y+GDC_fontc[GDC_SMALL].h, arrwclr );
	if( up )																/*   oo   */
		{																	/*  uoou  */
		gdImageSetPixel( im, x,   y+2, arrwclr );							/* uuoouu */
		gdImageSetPixel( im, x+1, y+2, arrwclr );							/*   oo   */
		gdImageSetPixel( im, x+4, y+2, arrwclr );							/*   oo   */
		gdImageSetPixel( im, x+5, y+2, arrwclr );							/*   oo   */
		gdImageSetPixel( im, x+1, y+1, arrwclr );							/*   oo   */
		gdImageSetPixel( im, x+4, y+1, arrwclr );							/*   oo   */
		}																	/*   oo   */
	else																	/* ddoodd */
		{																	/*  dood  */
		gdImageSetPixel( im, x,   y+(GDC_fontc[GDC_SMALL].h-2), arrwclr );	/*   oo   */
		gdImageSetPixel( im, x+1, y+(GDC_fontc[GDC_SMALL].h-2), arrwclr );
		gdImageSetPixel( im, x+4, y+(GDC_fontc[GDC_SMALL].h-2), arrwclr );
		gdImageSetPixel( im, x+5, y+(GDC_fontc[GDC_SMALL].h-2), arrwclr );
		gdImageSetPixel( im, x+1, y+(GDC_fontc[GDC_SMALL].h-1), arrwclr );
		gdImageSetPixel( im, x+4, y+(GDC_fontc[GDC_SMALL].h-1), arrwclr );
		}
}
#endif


#define SET_3D_POLY( gdp, x1, x2, y1, y2, xoff, yoff )						\
								gdp[0].x  = x1,        gdp[0].y = y1,		\
								gdp[1].x  = x1+(xoff), gdp[1].y = y1-yoff,	\
								gdp[2].x  = x2+(xoff), gdp[2].y = y2-yoff,	\
								gdp[3].x  = x2,        gdp[3].y = y2
/* ------------------------------------------------------------------------- */
/* vals in pixels */
/* ref is front plane */
/* allows for intersecting 3D lines      */
/*  (also used for single 3D lines >:-Q  */
struct YS { int y1; int y2; float slope; int lnclr; int shclr; };
static int qcmpr( const void *a, const void *b )
	{ if( ((struct YS*)a)->y2 < ((struct YS*)b)->y2 ) return 1;
	  if( ((struct YS*)a)->y2 > ((struct YS*)b)->y2 ) return -1;
	  return 0; }
void
draw_3d_line( gdImagePtr	im,
			  int			y0,
			  int			x1,
			  int			x2,
			  int			y1[],
			  int			y2[],
			  int			xdepth,
			  int			ydepth,
			  int			num_sets,
			  int			clr[],
			  int			clrshd[] )
{
#define F(x,i)	(int)( (float)((x)-x1)*slope[i]+(float)y1[i] )
	float		depth_slope  = xdepth==0? MAXFLOAT: (float)ydepth/(float)xdepth;
	float		
#if defined(USE_ALLOCA) || defined(HAVE_ALLOCA)
				*slope = (float*)alloca (num_sets * sizeof (float));
#else
				slope[num_sets];
#endif /* USE_ALLOCA */
	int			i;
	int			x;
	gdPoint
#ifdef USE_ALLOCA
				*poly = (gdPoint*)alloca (4 * sizeof (gdPoint));
#else
				poly[4];
#endif /* USE_ALLOCA */
	struct YS
#ifdef USE_ALLOCA
			*ypts = (struct YS*)alloca (num_sets * sizeof (struct YS));
#else
			ypts[num_sets];
#endif /* USE_ALLOCA */

	for( i=0; i<num_sets; ++i )
		{
		/* lnclr[i] = clr[i];
		 shclr[i] = clrshd[i];*/
		slope[i] = x2==x1? MAXFLOAT: (float)(y2[i]-y1[i])/(float)(x2-x1);
		}

	for( x=x1+1; x<=x2; ++x )
		{
		for( i=0; i<num_sets; ++i )		/* load set of points */
			{
			ypts[i].y1    = F(x-1,i);
			ypts[i].y2    = F(x,i);
			ypts[i].lnclr = clr[i];
			ypts[i].shclr = clrshd[i];
			ypts[i].slope = slope[i];
			}						/*  sorted "lowest" first */
		qsort( ypts, num_sets, sizeof(struct YS), qcmpr );
									/* put out in that order */
		for( i=0; i<num_sets; ++i )
			{						/* top */
			SET_3D_POLY( poly, x-1, x, ypts[i].y1, ypts[i].y2, xdepth, ydepth );
			gdImageFilledPolygon( im, poly, 4,			/* depth_slope ever < 0 ? */
								  -ypts[i].slope>depth_slope? ypts[i].shclr: ypts[i].lnclr );
			if( x == x1+1 )								/* edging */
				gdImageLine( im,
							 x-1, ypts[i].y2,
							 x-1+xdepth, ypts[i].y2-ydepth,
							 -ypts[i].slope<=depth_slope? ypts[i].shclr: ypts[i].lnclr );
			}
		}
}

/* ------------------------------------------------------------------------- */
/* vals in pixels */
/* ref is front plane */
void
draw_3d_area( gdImagePtr		im,
			 int				x1,
			 int				x2,
			 int				y0,			/* drawn from 0 */
			 int				y1,
			 int				y2,
			 int				xdepth,
			 int				ydepth,
			 int				clr,
			 int				clrshd )
{

	gdPoint     poly[4];
	int			y_intercept = 0;			/* if xdepth || ydepth */
 
	if( xdepth || ydepth )
		{
		float		line_slope   = x2==x1?    MAXFLOAT: (float)-(y2-y1) / (float)(x2-x1);
		float		depth_slope  = xdepth==0? MAXFLOAT: (float)ydepth/(float)xdepth;

		y_intercept = (y1 > y0 && y2 < y0) ||			/* line crosses y0 */
					   (y1 < y0 && y2 > y0)?
							(int)((1.0/ABS(line_slope))*(float)(ABS(y1-y0)))+x1:
							0;					/* never */
												/* edging along*/
		gdImageLine( im, x1+xdepth, y0-ydepth, x2+xdepth, y0-ydepth, clrshd );

		SET_3D_POLY( poly, x1, x2, y1, y2, xdepth, ydepth );	/* top */
		gdImageFilledPolygon( im, poly, 4, line_slope>depth_slope? clrshd: clr );

		SET_3D_POLY( poly, x1, x2, y0, y0, xdepth, ydepth+1 );	/* along y axis */
		gdImageFilledPolygon( im, poly, 4, clr );

		SET_3D_POLY( poly, x2, x2, y0, y2, xdepth, ydepth );		/* side */
		gdImageFilledPolygon( im, poly, 4, clrshd );

		if( y_intercept )
			gdImageLine( im, y_intercept,        y0,
							 y_intercept+xdepth, y0-ydepth, clrshd );/* edging */
		gdImageLine( im, x1, y0, x1+xdepth, y0-ydepth, clrshd );	/* edging */
		gdImageLine( im, x2, y0, x2+xdepth, y0-ydepth, clrshd );	/* edging */

		/* SET_3D_POLY( poly, x2, x2, y0, y2, xdepth, ydepth );	
		 gdImageFilledPolygon( im, poly, 4, clrshd );
		 */

		gdImageLine( im, x1, y1, x1+xdepth, y1-ydepth, clrshd );	/* edging */
		gdImageLine( im, x2, y2, x2+xdepth, y2-ydepth, clrshd );	/* edging */
		}

	if( y1 == y2 )				/* bar rect */
		SET_RECT( poly, x1, x2, y0, y1 );		/* front */
	else
		{
		poly[0].x = x1;	poly[0].y = y0;
		poly[1].x = x2;	poly[1].y = y0;
		poly[2].x = x2;	poly[2].y = y2;
		poly[3].x = x1;	poly[3].y = y1;
		}
	gdImageFilledPolygon( im, poly, 4, clr );

	gdImageLine( im, x1, y0, x2, y0, clrshd );	/* edging along y0 */

	if( (xdepth || ydepth) &&		/* front edging only on 3D */
		(y1<y0 || y2<y0) )		/* and only above y0 */
		{
		if( y1 > y0 && y2 < y0 )		/* line crosses from below y0 */
			gdImageLine( im, y_intercept, y0, x2, y2, clrshd );
		else
		if( y1 < y0 && y2 > y0 )		/* line crosses from above y0 */
			gdImageLine( im, x1, y1, y_intercept, y0, clrshd );
		else							/* completely above */
			gdImageLine( im, x1, y1, x2, y2, clrshd );
		}
}

/* ------------------------------------------------------------------------- */
/* vals in pixels */
/* ref is front plane */
void
draw_3d_bar( gdImagePtr			im,
			 int				x1,
			 int				x2,
			 int				y0,
			 int				yhigh,
			 int				xdepth,
			 int				ydepth,
			 int				clr,
			 int				clrshd )
{
#define SET_3D_BAR( gdp, x1, x2, y1, y2, xoff, yoff )						\
								gdp[0].x  = x1,        gdp[0].y = y1,		\
								gdp[1].x  = x1+(xoff), gdp[1].y = y1-yoff,	\
								gdp[2].x  = x2+(xoff), gdp[2].y = y2-yoff,	\
								gdp[3].x  = x2,        gdp[3].y = y2

	gdPoint     poly[4];
	int			usd = MIN( y0, yhigh );		/* up-side-down bars */


	if( xdepth || ydepth )
		{
		if( y0 != yhigh )				/* 0 height? */
			{
			SET_3D_BAR( poly, x2, x2, y0, yhigh, xdepth, ydepth );	/* side */
			gdImageFilledPolygon( im, poly, 4, clrshd );
			}

		SET_3D_BAR( poly, x1, x2, usd, usd, xdepth, ydepth );		/* top */
		gdImageFilledPolygon( im, poly, 4, clr );
		}

	SET_RECT( poly, x1, x2, y0, yhigh );							/* front */
	gdImageFilledPolygon( im, poly, 4, clr );

	if( xdepth || ydepth )
		gdImageLine( im, x1, usd, x2, usd, clrshd );
}

/* ------------------------------------------------------------------------- */
struct BS { float y1; float y2; int clr; int shclr; };
static int barcmpr( const void *a, const void *b )
	{ if( ((struct BS*)a)->y2 < ((struct BS*)b)->y2 ) return -1;
	  if( ((struct BS*)a)->y2 > ((struct BS*)b)->y2 ) return 1;
	  return 0; }

/* ------------------------------------------------------------------------- */
/* little/no error checking  0:    ok,
							 -ret: error no graph output
							 ret:  error graph out
 watch out for # params and array sizes==num_points
*/
int
out_graph( short		GIFWIDTH,		/* no check for a gif that's too small to fit */
		   short		GIFHEIGHT,		/* needed info (labels, etc), could core dump */
		   FILE			*gif_fptr,		/* open file pointer (gif out) */
		   GDC_CHART_T	type,
		   int			num_points,     /* points along x axis (even iterval) */
							/*	all arrays dependant on this  */
		   char			*xlbl[],	/* array of xlabels */
		   int			num_sets,
						... )
{
	va_list		ap;
	int			i, j;

	int			graphwidth;
	int			grapheight;
	gdImagePtr	im;
	gdImagePtr	bg_img = NULL;

	float		xorig, yorig, vyorig = 0.0;
	float		yscl     = 0.0;
	float		vyscl    = 0.0;
	float		xscl     = 0.0;
	float		vhighest = -MAXFLOAT;
	float		vlowest  = MAXFLOAT;
	float		highest  = -MAXFLOAT;
	float		lowest   = MAXFLOAT;

	char		do_vol = ( type == GDC_COMBO_HLC_BAR   ||		/* aka: combo */
						   type == GDC_COMBO_HLC_AREA  ||
						   type == GDC_COMBO_LINE_BAR  ||
						   type == GDC_COMBO_LINE_AREA ||
						   type == GDC_3DCOMBO_HLC_BAR ||
						   type == GDC_3DCOMBO_HLC_AREA||
						   type == GDC_3DCOMBO_LINE_BAR||
						   type == GDC_3DCOMBO_LINE_AREA );
	char		threeD = ( type == GDC_3DAREA          ||
						   type == GDC_3DLINE          ||
						   type == GDC_3DBAR           ||
						   type == GDC_3DHILOCLOSE     ||
						   type == GDC_3DCOMBO_HLC_BAR ||
						   type == GDC_3DCOMBO_HLC_AREA||
						   type == GDC_3DCOMBO_LINE_BAR||
						   type == GDC_3DCOMBO_LINE_AREA );
	char		num_hlc_sets =
						 ( type == GDC_COMBO_HLC_BAR   ||
						   type == GDC_COMBO_HLC_AREA  ||
						   type == GDC_3DCOMBO_HLC_BAR ||
						   type == GDC_3DCOMBO_HLC_AREA||
						   type == GDC_3DHILOCLOSE     ||
						   type == GDC_HILOCLOSE )? num_sets: 0;
	char		do_bar = ( type == GDC_3DBAR ||		/* offset X objects to leave */
						   type == GDC_BAR );	/*  room at X(0) and X(n) */
																/*  i.e., not up against Y axes*/
	char		do_ylbl_fractions = 							/* %f format not given, or*/
						 ( !GDC_ylabel_fmt ||					/*  format doesn't have a %,g,e,E,f or F*/
						   strlen(GDC_ylabel_fmt) == strcspn(GDC_ylabel_fmt,"%geEfF") );
	float		ylbl_interval  = 0.0;
	int			num_lf_xlbls   = 0;
	int			xdepth_3Dtotal = 0;
	int			ydepth_3Dtotal = 0;
	int			xdepth_3D      = 0;		/* affects PX()*/
	int			ydepth_3D      = 0;		/* affects PY() and PV()*/
	int			hlf_barwdth	   = 0;		/* half bar widths*/
	int			hlf_hlccapwdth = 0;		/* half cap widths for HLC_I_CAP and DIAMOND*/
	int			annote_len     = 0,
				annote_hgt     = 0;

	/* args */
	int			setno = 0;				/* affects PX() and PY()*/
	int			 _dim_ =  (
						type == GDC_HILOCLOSE        ||
						type == GDC_3DHILOCLOSE      ||
						type == GDC_3DCOMBO_HLC_BAR  ||
						type == GDC_3DCOMBO_HLC_AREA ||
						type == GDC_COMBO_HLC_BAR    ||
						type == GDC_COMBO_HLC_AREA? 
(num_sets = num_sets * 3):	/* 1 more last set is vol*/
						type == GDC_COMBO_LINE_BAR   ||
						type == GDC_3DCOMBO_LINE_BAR ||
						type == GDC_3DCOMBO_LINE_AREA||
						type == GDC_COMBO_LINE_AREA? num_sets:num_sets );
#ifdef USE_ALLOCA
	float		**uvals = (float**)alloca (_dim_ * sizeof (float));
#else
	float		*uvals[ _dim_];
#endif /* USE_ALLOCA */

	float		*uvol = NULL;

	int			BGColor,
				LineColor,
				PlotColor,
				GridColor,
				VolColor = 0,
#ifdef USE_ALLOCA
				*ExtVolColor = (int*)alloca (num_points * sizeof (int)),
#else
				ExtVolColor[num_points],
#endif /* USE_ALLOCA */
/*				ArrowDColor,*/
/*				ArrowUColor,*/
				AnnoteColor = 0,
#ifdef USE_ALLOCA
				*ExtColor = (int*)alloca (num_sets * num_points * sizeof (int));
#else
				ExtColor[num_sets][num_points];
#endif /* USE_ALLOCA */
																/* shade colors only with 3D*/
/*	int			ExtColorShd[threeD?1:num_sets][threeD?1:num_points];*/ /* compiler limitation*/
	int
#ifdef USE_ALLOCA
					*ExtColorShd = (int*)alloca (num_sets * num_points * sizeof (int));
#else
					ExtColorShd[num_sets][num_points];
#endif /* USE_ALLOCA */

	/* idiot checks */
	if( GIFWIDTH<=0 || GIFHEIGHT<=0 || (!gif_fptr && GDC_generate_gif) )
		return -1;
	if( num_points <= 0 )
		{
		out_err( GIFWIDTH, GIFHEIGHT, gif_fptr, GDC_BGColor, GDC_LineColor, "No Data Available" );
		return 1;
		}

	load_font_conversions();
	if( GDC_thumbnail )
		{
		GDC_grid = FALSE;
		GDC_xaxis = FALSE;
		GDC_yaxis = FALSE;
		}

	/* ----- get args  va number of float arrays -----*/
	va_start( ap, num_sets );
	for( i=0; i<num_sets; ++i )
		uvals[i] = va_arg(ap, float*);
	if( do_vol )
		uvol = va_arg(ap, float*);
	va_end(ap);

	/* ----- highest & lowest values ----- */
	if( GDC_stack_type == GDC_STACK_SUM ) 		/* need to walk sideways*/
		for( j=0; j<num_points; ++j )
			{
			float	set_sum = 0.0;
			for( i=0; i<num_sets; ++i )
				if( uvals[i][j] != GDC_NOVALUE )
					{
					set_sum += uvals[i][j];
					highest = MAX( highest, set_sum );
					lowest  = MIN( lowest,  set_sum );
					}
			}
	else
	if( GDC_stack_type == GDC_STACK_LAYER )		/* need to walk sideways*/
		for( j=0; j<num_points; ++j )
			{
			float	neg_set_sum = 0.0,
					pos_set_sum = 0.0;
			for( i=0; i<num_sets; ++i )
				if( uvals[i][j] != GDC_NOVALUE )
				{
					if( uvals[i][j] < 0.0 )
						neg_set_sum += uvals[i][j];
					else
						pos_set_sum += uvals[i][j];
				}
			lowest  = MIN( lowest,  MIN(neg_set_sum,pos_set_sum) );
			highest = MAX( highest, MAX(neg_set_sum,pos_set_sum) );
			}
	else
		for( i=0; i<num_sets; ++i )
			for( j=0; j<num_points; ++j )
				if( uvals[i][j] != GDC_NOVALUE )
					{
					highest = MAX( uvals[i][j], highest );
					lowest  = MIN( uvals[i][j], lowest );
					}
	if( GDC_scatter )
	  for( i=0; i<GDC_num_scatter_pts; ++i )
		{
		highest = MAX( (GDC_scatter+i)->val, highest );
		lowest  = MIN( (GDC_scatter+i)->val, lowest  );
		}
	if( do_vol )								/* for now only one combo set allowed*/
		{
		/* vhighest = 1.0;*/
		/* vlowest  = 0.0;*/
		for( j=0; j<num_points; ++j )
			if( uvol[j] != GDC_NOVALUE )
				{
				vhighest = MAX( uvol[j], vhighest );
				vlowest  = MIN( uvol[j], vlowest );
				}
		if( vhighest == -MAXFLOAT )			/* no values*/
			vhighest = 1.0;						/* for scaling, need a range*/
		else
		if( vhighest < 0.0 )
			vhighest = 0.0;
		if( vlowest > 0.0 || vlowest == MAXFLOAT )
			vlowest = 0.0;						/* vol should always start at 0*/
		}

	if( lowest == MAXFLOAT )
		lowest = 0.0;
	if( highest == -MAXFLOAT )
		highest = 1.0;							/* need a range*/
	if( type == GDC_AREA  ||					/* bars and area should always start at 0*/
		type == GDC_BAR   ||
		type == GDC_3DBAR ||
		type == GDC_3DAREA )
		{
		if( highest < 0.0 )
			highest = 0.0;
		else
		if( lowest > 0.0 )						/* negs should be drawn from 0*/
			lowest = 0.0;
		}

	if( GDC_requested_ymin != GDC_NOVALUE && GDC_requested_ymin < lowest )
		lowest = GDC_requested_ymin;
	if( GDC_requested_ymax != GDC_NOVALUE && GDC_requested_ymax > highest )
		highest = GDC_requested_ymax;
	

	/* ----- graph height and width within the gif height width ----- */
	/* grapheight/height is the actual size of the scalable graph */
	{
	int	title_hgt  = GDC_title? 2				/* title? horizontal text line(s) */
								+ cnt_nl(GDC_title,(int*)NULL)*GDC_fontc[GDC_title_size].h
								+ 2:
								2;
	int	xlabel_hgt = 0;
	int	xtitle_hgt = GDC_xtitle? 1+GDC_fontc[GDC_xtitle_size].h+1: 0;
	int	ytitle_hgt = GDC_ytitle? 1+GDC_fontc[GDC_ytitle_size].h+1: 0;
	int	vtitle_hgt = do_vol&&GDC_ytitle2? 1+GDC_fontc[GDC_ytitle_size].h+1: 0;
	int	ylabel_wth = 0;
	int	vlabel_wth = 0;

	int	xtics       = GDC_grid||GDC_xaxis? 1+2: 0;
	int	ytics       = GDC_grid||GDC_yaxis? 1+3: 0;
	int	vtics       = GDC_yaxis&&do_vol? 3+1: 0;


#define	HYP_DEPTH	( (double)((GIFWIDTH+GIFHEIGHT)/2) * ((double)GDC_3d_depth)/100.0 )
#define RAD_DEPTH	( (double)GDC_3d_angle*2*M_PI/360 )
	xdepth_3D      = threeD? (int)( cos(RAD_DEPTH) * HYP_DEPTH ): 0;
	ydepth_3D      = threeD? (int)( sin(RAD_DEPTH) * HYP_DEPTH ): 0;
	xdepth_3Dtotal = xdepth_3D*(GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets:
																			   num_sets:
																 1 );
	ydepth_3Dtotal = ydepth_3D*(GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets:
																			   num_sets:
																 1 );
	annote_hgt = GDC_annotation && *(GDC_annotation->note)?
					1 +											/* space to note */
					(1+GDC_fontc[GDC_annotation_font].h) *		/* number of '\n' substrs */
					cnt_nl(GDC_annotation->note,&annote_len) +
					1 +											/* space under note */
					2: 0;										/* space to chart */
	annote_len *= GDC_fontc[GDC_annotation_font].w;

	if( GDC_xaxis && xlbl )
		{
		int biggest     = 0 - (MAXINT);

		for( i=0; i<num_points; ++i )
			{
			int		len = 0;
																/* longest "...\n" segment*/
			for( len=0, j=0; xlbl[i][j]; ++len, ++j )
				if( xlbl[i][j] == '\n' )
					{
					biggest = MAX( len, biggest );
					++num_lf_xlbls;
					len = 0;
					}
			biggest = MAX( len, biggest );				/* last seg*/
			}
		xlabel_hgt = 1+ biggest*GDC_fontc[GDC_xaxisfont_size].w +1;
		}
	
	grapheight = GIFHEIGHT - ( xtics          +
							   xtitle_hgt     +
							   xlabel_hgt     +
							   title_hgt      +
							   annote_hgt     +
							   ydepth_3Dtotal +
							   2 );
	if( GDC_hard_size && GDC_hard_grapheight )				/* user wants to use his */
		grapheight = GDC_hard_grapheight;
	GDC_hard_grapheight = grapheight;
															/* before width can be known...*/
	/* ----- y labels intervals ----- */
	{
	float	tmp_highest;
															/* possible y gridline points */
	float	ypoints[] = { 1.0/64.0, 1.0/32.0, 1.0/16.0, 1.0/8.0, 1.0/4.0, 1.0/2.0,
						  1.0,      2.0,      3.0,      5.0,     10.0,    25.0,
						  50.0,     100.0,    250.0,    500.0,   1000.0,  2500,    5000.0,
						  10000.0,  25000.0,  50000.0,  100000.0,500000.0,1000000, 5000000,
						  10000000 };
	#define	NUM_YPOINTS	(sizeof(ypoints) / sizeof(float))
	int		max_num_ylbls;
	int		longest_ylblen = 0;
															/* maximum y lables that'll fit... */
	max_num_ylbls = grapheight / (3+GDC_fontc[GDC_yaxisfont_size==GDC_TINY? GDC_yaxisfont_size+1:
																			GDC_yaxisfont_size].h);
	if( max_num_ylbls < 3 )
		{
		/* gdImageDestroy(im);		haven't yet created it */
		out_err( GIFWIDTH, GIFHEIGHT,
				 gif_fptr,
				 GDC_BGColor, GDC_LineColor,
				 "Insificient Height" );
		return 2;
		}

														/* one "space" interval above + below */
	for( i=1; i<NUM_YPOINTS; ++i )
		/* if( ypoints[i] > ylbl_interval )*/
		/*	break;*/
		if( (highest-lowest)/ypoints[i] < ((float)max_num_ylbls-(1.0+1.0))
											* (float)GDC_ylabel_density/100.0 )
			break;
	/* gotta go through the above loop to catch the 'tweeners :-| */

	ylbl_interval = GDC_requested_yinterval != GDC_NOVALUE &&
					GDC_requested_yinterval > ypoints[i-1]?	  GDC_requested_yinterval:
															  ypoints[i-1];

														/* perform floating point remainders */
														/* gonculate largest interval-point < lowest */
	if( lowest != 0.0 &&
		lowest != GDC_requested_ymin )
		{
		if( lowest < 0.0 )
			lowest -= ylbl_interval;
		/* lowest = (lowest-ypoints[0]) -*/
		/* 			( ( ((lowest-ypoints[0])/ylbl_interval)*ylbl_interval ) -*/
		/* 			   ( (float)((int)((lowest-ypoints[0])/ylbl_interval))*ylbl_interval ) );*/
		lowest = ylbl_interval * (float)(int)((lowest-ypoints[0])/ylbl_interval);
		}
														/* find smallest interval-point > highest */
	tmp_highest = lowest;
	do	/* while( (tmp_highest += ylbl_interval) <= highest )*/
		{
		int		nmrtr, dmntr, whole;
		char	*price_to_str( float, int*, int*, int*, char* );
		int		lbl_len;
		char	foo[32];

		if( GDC_yaxis )
			{											/* XPG2 compatibility */
			sprintf( foo, do_ylbl_fractions? "%.0f": GDC_ylabel_fmt, tmp_highest );
			lbl_len = ylbl_interval<1.0? strlen( price_to_str(tmp_highest,
															  &nmrtr,
															  &dmntr,
															  &whole,
															  do_ylbl_fractions? NULL: GDC_ylabel_fmt) ):
										 strlen( foo );
			longest_ylblen = MAX( longest_ylblen, lbl_len );
			}
		} while( (tmp_highest += ylbl_interval) <= highest );
	ylabel_wth = longest_ylblen * GDC_fontc[GDC_yaxisfont_size].w;
	highest = GDC_requested_ymax==GDC_NOVALUE? tmp_highest:
											   MAX( GDC_requested_ymax, highest );

	if( do_vol )
		{
		float	num_yintrvls = (highest-lowest) / ylbl_interval;
															/* no skyscrapers */
		if( vhighest != 0.0 )
			vhighest += (vhighest-vlowest) / (num_yintrvls*2.0);
		if( vlowest != 0.0 )
			vlowest -= (vhighest-vlowest) / (num_yintrvls*2.0);

		if( GDC_yaxis2 )
			{
			char	svlongest[32];
			int		lbl_len_low  = sprintf( svlongest, GDC_ylabel2_fmt? GDC_ylabel2_fmt: "%.0f", vlowest );
			int		lbl_len_high = sprintf( svlongest, GDC_ylabel2_fmt? GDC_ylabel2_fmt: "%.0f", vhighest );
			vlabel_wth = 1
						 + MAX( lbl_len_low,lbl_len_high ) * GDC_fontc[GDC_yaxisfont_size].w;
			}
		}
	}

	graphwidth = GIFWIDTH - ( ( (GDC_hard_size && GDC_hard_xorig)? GDC_hard_xorig:
																   ( ytitle_hgt +
																     ylabel_wth +
																     ytics ) )
							  + vtics
							  + vtitle_hgt
							  + vlabel_wth
							  + xdepth_3Dtotal );
	if( GDC_hard_size && GDC_hard_graphwidth )				/* user wants to use his */
		graphwidth = GDC_hard_graphwidth;
	GDC_hard_graphwidth = graphwidth;

	/* ----- scale to gif size ----- */
	/* offset to 0 at lower left (where it should be) */
	xscl = (float)(graphwidth-xdepth_3Dtotal) / (float)(num_points + (do_bar?2:0));
	yscl = -((float)grapheight) / (float)(highest-lowest);
	if( do_vol )
		{
		float	hilow_diff = vhighest-vlowest==0.0? 1.0: vhighest-vlowest;

		vyscl = -((float)grapheight) / hilow_diff;
		vyorig = (float)grapheight
				 + ABS(vyscl) * MIN(vlowest,vhighest)
				 + ydepth_3Dtotal
				 + title_hgt
				 + annote_hgt;
		}
	xorig = (float)( GIFWIDTH - ( graphwidth +
								  vtitle_hgt +
								  vtics      +
								  vlabel_wth ) );
	if( GDC_hard_size && GDC_hard_xorig )
		xorig = GDC_hard_xorig;
	GDC_hard_xorig = xorig;
/*	yorig = (float)grapheight + ABS(yscl * lowest) + ydepth_3Dtotal + title_hgt;*/
	yorig = (float)grapheight
				+ ABS(yscl) * MIN(lowest,highest)
				+ ydepth_3Dtotal
				+ title_hgt
				+ annote_hgt;
/*????	if( GDC_hard_size && GDC_hard_yorig )			*/
/*????		yorig = GDC_hard_yorig;*/
	GDC_hard_yorig = yorig;

	hlf_barwdth     = (int)( (float)(PX(2)-PX(1)) * (((float)GDC_bar_width/100.0)/2.0) );	/* used only for bars*/
	hlf_hlccapwdth  = (int)( (float)(PX(2)-PX(1)) * (((float)GDC_HLC_cap_width/100.0)/2.0) );
	}
	/* scaled, sized, ready*/


	/* ----- OK start the graphic ----- */
	if( (GDC_hold_img & GDC_REUSE_IMAGE) &&
		GDC_image != (void*)NULL )
		im = GDC_image;
	else
		im = gdImageCreate( GIFWIDTH, GIFHEIGHT );


	BGColor        = gdImageColorAllocate( im, l2gdcal(GDC_BGColor) );
	LineColor      = clrallocate( im, GDC_LineColor );
	PlotColor      = clrallocate( im, GDC_PlotColor );
	GridColor      = clrallocate( im, GDC_GridColor );
	if( do_vol )
	  {
	  VolColor     = clrallocate( im, GDC_VolColor );
	  for( i=0; i<num_points; ++i )
		if( GDC_ExtVolColor )
		  ExtVolColor[i] = clrallocate( im, GDC_ExtVolColor[i] );
		else
		  ExtVolColor[i] = VolColor;
	  }
/*	ArrowDColor    = gdImageColorAllocate( im, 0xFF,    0, 0 );*/
/*	ArrowUColor    = gdImageColorAllocate( im,    0, 0xFF, 0 );*/
	if( GDC_annotation )
		AnnoteColor = clrallocate( im, GDC_annotation->color );

	/* attempt to import optional background image */
	if( GDC_BGImage )
		{
		FILE	*in = fopen(GDC_BGImage, "rb");
		if( !in )
			{
			; /* Cant load background image, drop it*/
			}
		else
			{
			if( (bg_img = gdImageCreateFromGif(in)) != 0 )					/* =*/
				{
				int	bgxpos = gdImageSX(bg_img)<GIFWIDTH?  GIFWIDTH/2 - gdImageSX(bg_img)/2:  0,
					bgypos = gdImageSY(bg_img)<GIFHEIGHT? GIFHEIGHT/2 - gdImageSY(bg_img)/2: 0;


				if( gdImageSX(bg_img) > GIFWIDTH ||				/* resize only if too big*/
					gdImageSY(bg_img) > GIFHEIGHT )				/*  [and center]*/
					{
					gdImageCopyResized( im, bg_img,				/* dst, src*/
										bgxpos, bgypos,			/* dstX, dstY*/
										0, 0,					/* srcX, srcY*/
										GIFWIDTH, GIFHEIGHT,	/* dstW, dstH*/
										GIFWIDTH, GIFHEIGHT );	/* srcW, srcH*/
					}
				else											/* just center*/
					gdImageCopy( im, bg_img,					/* dst, src*/
								 bgxpos, bgypos,				/* dstX, dstY*/
								 0, 0,							/* srcX, srcY*/
								 GIFWIDTH, GIFHEIGHT );			/* W, H*/
				}
			fclose(in);
			}
		}

	for( j=0; j<num_sets; ++j )
		for( i=0; i<num_points; ++i )
			if( GDC_ExtColor )
				{
				unsigned long	ext_clr = *(GDC_ExtColor+num_points*j+i);

				ExtColor I(j,i)            = clrallocate( im, ext_clr );
				if( threeD )
					ExtColorShd I(j,i)     = clrshdallocate( im, ext_clr );
				}
			else if( GDC_SetColor )
				{
				int	set_clr = GDC_SetColor[j];
				ExtColor I(j,i)     = clrallocate( im, set_clr );
				if( threeD )
				 ExtColorShd I(j,i) = clrshdallocate( im, set_clr );
				}
			else
				{
				ExtColor I(j,i)     = PlotColor;
				if( threeD )
				 ExtColorShd I(j,i) = clrshdallocate( im, GDC_PlotColor );
				}
			

	if( GDC_transparent_bg )
		gdImageColorTransparent( im, BGColor );

	if( GDC_title )
		{
		int	tlen;
		int	titlecolor = clrallocate( im, GDC_TitleColor );

		cnt_nl( GDC_title, &tlen );
		GDCImageStringNL( im,
						  &GDC_fontc[GDC_title_size],
						  GIFWIDTH/2 - tlen*GDC_fontc[GDC_title_size].w/2,
						  0,
						  GDC_title,
						  titlecolor,
						  GDC_JUSTIFY_CENTER );
		}
	if( GDC_xtitle )
		{
		int	titlecolor = GDC_XTitleColor==GDC_DFLTCOLOR? 
							PlotColor: clrallocate( im, GDC_XTitleColor );
		gdImageString( im,
					   GDC_fontc[GDC_xtitle_size].f,
					   GIFWIDTH/2 - strlen(GDC_xtitle)*GDC_fontc[GDC_xtitle_size].w/2,
					   GIFHEIGHT-GDC_fontc[GDC_xtitle_size].h-1,
					   (u_char*)GDC_xtitle,
					   titlecolor );
		}


	/* ----- start drawing ----- */
	/* ----- backmost first - grid & labels ----- */
	if( GDC_grid || GDC_yaxis )
		{	/* grid lines & y label(s) */
		float	tmp_y = lowest;
		int		labelcolor = GDC_YLabelColor==GDC_DFLTCOLOR? 
							 LineColor: clrallocate( im, GDC_YLabelColor );
		int		label2color = GDC_YLabel2Color==GDC_DFLTCOLOR? 
							  VolColor: clrallocate( im, GDC_YLabel2Color );

		/* step from lowest to highest puting in labels and grid at interval points */
		/* since now "odd" intervals may be requested, try to step starting at 0,   */
		/* if lowest < 0 < highest                                                  */
		for( i=-1; i<=1; i+=2 )									/* -1, 1*/
			{
			if( i == -1 ) {	if( lowest >= 0.0 )					/*	all pos plotting*/
								continue;
							else
								tmp_y = MIN( 0, highest );		/*	step down to lowest*/
					}
			if( i == 1 )   {if( highest <= 0.0 )				/*	all neg plotting*/
								continue;
							else
								tmp_y = MAX( 0, lowest );		/*	step up to highest*/
					}
#if 0
//			if( !(highest > 0 && lowest < 0) )					/* doesn't straddle 0*/
/*				{*/
//				if( i == -1 )									/* only do once: normal*/
/*					continue;*/
/*				}*/
/*			else*/
/*				tmp_y = 0;*/
#endif
			do	/* while( (tmp_y (+-)= ylbl_interval) < [highest,lowest] )*/
				{
				int		n, d, w;
				char	*price_to_str( float, int*, int*, int*, char* );
				char	nmrtr[3+1], dmntr[3+1], whole[8];
				char	all_whole = ylbl_interval<1.0? FALSE: TRUE;

				char	*ylbl_str = price_to_str( tmp_y,&n,&d,&w,
												  do_ylbl_fractions? NULL: GDC_ylabel_fmt );
				if( do_ylbl_fractions )
					{
					sprintf( nmrtr, "%d", n );
					sprintf( dmntr, "%d", d );
					sprintf( whole, "%d", w );
					}

				if( GDC_grid )
					{
					int	x1, x2, y1, y2;
					/* int	gridline_clr = tmp_y == 0.0? LineColor: GridColor;*/
																		/* tics*/
					x1 = PX(0);		y1 = PY(tmp_y);
					gdImageLine( im, x1-2, y1, x1, y1, GridColor );
					setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets:
																		   num_sets:
															 1;			/* backmost*/
					x2 = PX(0);		y2 = PY(tmp_y);						/* w/ new setno*/
					gdImageLine( im, x1, y1, x2, y2, GridColor );		/* depth for 3Ds*/
					gdImageLine( im, x2, y2, PX(num_points-1+(do_bar?2:0)), y2, GridColor );
					setno = 0;											/* set back to foremost*/
					}
				if( GDC_yaxis ) {
					if( do_ylbl_fractions )
						{
						if( w || (!w && !n && !d) )
							{
							gdImageString( im,
										   GDC_fontc[GDC_yaxisfont_size].f,
										   PX(0)-2-strlen(whole)*GDC_fontc[GDC_yaxisfont_size].w
												  - ( (!all_whole)?
														(strlen(nmrtr)*GDC_fontc[GDC_yaxisfont_size-1].w +
														 GDC_fontc[GDC_yaxisfont_size].w                 +
														 strlen(nmrtr)*GDC_fontc[GDC_yaxisfont_size-1].w) :
														1 ),
										   PY(tmp_y)-GDC_fontc[GDC_yaxisfont_size].h/2,
										 (u_char*)whole,
										   labelcolor );
							}
						if( n )
							{
							gdImageString( im,
										   GDC_fontc[GDC_yaxisfont_size-1].f,
										   PX(0)-2-strlen(nmrtr)*GDC_fontc[GDC_yaxisfont_size-1].w
												  -GDC_fontc[GDC_yaxisfont_size].w
												  -strlen(nmrtr)*GDC_fontc[GDC_yaxisfont_size-1].w + 1,
										   PY(tmp_y)-GDC_fontc[GDC_yaxisfont_size].h/2 + 1,
										 (u_char*)nmrtr,
										   labelcolor );
							gdImageString( im,
										   GDC_fontc[GDC_yaxisfont_size].f,
										   PX(0)-2-GDC_fontc[GDC_yaxisfont_size].w
												  -strlen(nmrtr)*GDC_fontc[GDC_yaxisfont_size-1].w,
										   PY(tmp_y)-GDC_fontc[GDC_yaxisfont_size].h/2,
										  (u_char*)"/",
										   labelcolor );
							gdImageString( im,
										   GDC_fontc[GDC_yaxisfont_size-1].f,
										   PX(0)-2-strlen(nmrtr)*GDC_fontc[GDC_yaxisfont_size-1].w - 2,
										   PY(tmp_y)-GDC_fontc[GDC_yaxisfont_size].h/2 + 3,
										 (u_char*)dmntr,
										   labelcolor );
							}
						}
					else
						gdImageString( im,
									   GDC_fontc[GDC_yaxisfont_size].f,
									   PX(0)-2-strlen(ylbl_str)*GDC_fontc[GDC_yaxisfont_size].w,
									   PY(tmp_y)-GDC_fontc[GDC_yaxisfont_size].h/2,
									  (u_char*)ylbl_str,
									   labelcolor );

					}
				if( do_vol && GDC_yaxis2 )
					{
					char	vylbl[16];
																				/* opposite of PV(y) */
					sprintf( vylbl,
							 GDC_ylabel2_fmt? GDC_ylabel2_fmt: "%.0f",
							 ((float)(PY(tmp_y)+(setno*ydepth_3D)-vyorig))/vyscl );

					setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets:
																		   num_sets:
															 1; /* backmost*/
					gdImageLine( im, PX(num_points-1+(do_bar?2:0)), PY(tmp_y),
									 PX(num_points-1+(do_bar?2:0))+3, PY(tmp_y), GridColor );
					if( atof(vylbl) == 0.0 )									/* rounding can cause -0 */
						strcpy( vylbl, "0" );
					gdImageString( im,
								   GDC_fontc[GDC_yaxisfont_size].f,
								   PX(num_points-1+(do_bar?2:0))+6,
								   PY(tmp_y)-GDC_fontc[GDC_yaxisfont_size].h/2,
								   (u_char*)vylbl,
								   label2color );
					setno = 0;
					}
				}
			while( ((i>0) && ((tmp_y += ylbl_interval) < highest)) ||
				   ((i<0) && ((tmp_y -= ylbl_interval) > lowest)) );
			}

		/* catch last (bottom) grid line - specific to an "off" requested interval */
		if( GDC_grid && threeD )
			{
			setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets:
																   num_sets:
													 1;			/* backmost*/
			gdImageLine( im, PX(0), PY(lowest), PX(num_points-1+(do_bar?2:0)), PY(lowest), GridColor );
			setno = 0;											/* set back to foremost*/
			}

		/* vy axis title */
		if( do_vol && GDC_ytitle2 )
			{
			int	titlecolor = GDC_YTitle2Color==GDC_DFLTCOLOR? 
								VolColor: clrallocate( im, GDC_YTitle2Color );
			gdImageStringUp( im,
							 GDC_fontc[GDC_ytitle_size].f,
							 GIFWIDTH-(1+GDC_fontc[GDC_ytitle_size].h),
							 strlen(GDC_ytitle2)*GDC_fontc[GDC_ytitle_size].w/2 +
								grapheight/2,
							 (u_char*)GDC_ytitle2,
							 titlecolor );
			}

		/* y axis title */
		if( GDC_yaxis && GDC_ytitle )
			{
			int	ytit_len = strlen(GDC_ytitle)*GDC_fontc[GDC_ytitle_size].w;
			int	titlecolor = GDC_YTitleColor==GDC_DFLTCOLOR? 
								PlotColor: clrallocate( im, GDC_YTitleColor );
			gdImageStringUp( im,
							 GDC_fontc[GDC_ytitle_size].f,
							 0,
							 GIFHEIGHT/2 + ytit_len/2,
							 (u_char*)GDC_ytitle,
							 titlecolor );
			}
		}

	/* interviening set grids */
	/*  0 < setno < num_sets   non-inclusive, they've already been covered */
	if( GDC_grid && threeD )
		{
		for( setno=(GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets: num_sets: 1) - 1;
			 setno > 0;
			 --setno )
			{
			gdImageLine( im, PX(0), PY(lowest), PX(0), PY(highest), GridColor );
			gdImageLine( im, PX(0), PY(lowest), PX(num_points-1+(do_bar?2:0)), PY(lowest), GridColor );
			}
		setno = 0;
		}

	if( ( GDC_grid || GDC_0Shelf ) &&							/* line color grid at 0 */
		( (lowest < 0.0 && highest > 0.0) ||
		  (lowest < 0.0 && highest > 0.0) ) )
		{
		int	x1, x2, y1, y2;
																/* tics*/
		x1 = PX(0);		y1 = PY(0);
		gdImageLine( im, x1-2, y1, x1, y1, LineColor );
		setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets:
															   num_sets:
												 1;				/* backmost*/
		x2 = PX(0);		y2 = PY(0);								/* w/ new setno*/
		gdImageLine( im, x1, y1, x2, y2, LineColor );			/* depth for 3Ds*/
		gdImageLine( im, x2, y2, PX(num_points-1+(do_bar?2:0)), y2, LineColor );
		setno = 0;												/* set back to foremost*/
		}


	/* x ticks and xlables */
	if( GDC_grid || GDC_xaxis )
		{
		int		num_xlbls =										/* maximum x lables that'll fit */
																/* each xlbl + avg due to num_lf_xlbls */
					graphwidth /
						( (GDC_xlabel_spacing== (MAXSHORT) ?0:GDC_xlabel_spacing)+GDC_fontc[GDC_xaxisfont_size].h +
						  (num_lf_xlbls*(GDC_fontc[GDC_xaxisfont_size].h-1))/num_points );
		int		labelcolor = GDC_XLabelColor==GDC_DFLTCOLOR? 
							 LineColor: clrallocate( im, GDC_XLabelColor );

		for( i=0; i<num_points+(do_bar?2:0); ++i )
			if( (i%(1+num_points/num_xlbls) == 0) ||					/* # x labels are regulated*/
				(num_xlbls >= num_points)         ||
				GDC_xlabel_spacing == (MAXSHORT) )
				{
				int	xi = do_bar? i-1: i;

				if( GDC_grid )
					{
					int	x1, x2, y1, y2;
																		/* tics*/
					x1 = PX(i);		y1 = PY(lowest);
					gdImageLine( im, x1, y1, x1,  y1+2, GridColor );
					setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets:
																		   num_sets:
															 1; /* backmost*/
					x2 = PX(i);		y2 = PY(lowest);
					gdImageLine( im, x1, y1, x2,  y2, GridColor );		/* depth perspective*/
					gdImageLine( im, x2, y2, x2,  PY(highest), GridColor );
					setno = 0;											/* reset to foremost*/
					}

				if( !do_bar || (i>0 && xi<num_points) )
					if( GDC_xaxis && xlbl && xlbl[xi] && *(xlbl[xi]) )
						{
						/* waiting for GDCImageStringUpNL() */
#define					LBX		GDC_fontc[GDC_xaxisfont_size]
						int		xlen = 0;
						short	xstrs_num = cnt_nl( xlbl[xi], &xlen );
						char	
#ifdef USE_ALLOCA
								*sub_xlbl=(char*) alloca ((xlen+1) * sizeof (char));
#else
								sub_xlbl[xlen+1];
#endif /* USE_ALLOCA */
/*						int		xlbl_strt = -1+ PX((float)i+(float)(do_bar?((float)num_points/(float)num_xlbls):0.0)) - (int)((float)(LBX.h-2)*((float)xstrs_num/2.0));*/
						int		xlbl_strt = -1+ PX(i) - (int)((float)(LBX.h-2)*((float)xstrs_num/2.0));

						xlen      = -1;
						xstrs_num = -1;
						j = -1;
						do
							{
							++j;
							++xlen;
							sub_xlbl[xlen] = xlbl[xi][j];
							if( xlbl[xi][j] == '\n' ||
								xlbl[xi][j] == '\0' )
								{
								sub_xlbl[xlen] = '\0';
								++xstrs_num;
								gdImageStringUp( im,
												 LBX.f,
												 xlbl_strt + (LBX.h-1)*xstrs_num,
												 PY(lowest) + 2 + 1 + LBX.w*xlen,
									 (u_char*)sub_xlbl,
												 labelcolor );
								xlen = -1;
								}
							} while( xlbl[xi][j] );
#undef LBX
						}
				}
		}

	/* ----- solid poly region (volume) ----- */
	/*  so that grid lines appear under solid */
	if( do_vol )
		{
		setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets:
															   num_sets:
												 1; /* backmost*/
		if( type == GDC_COMBO_HLC_BAR    ||
			type == GDC_COMBO_LINE_BAR   ||
			type == GDC_3DCOMBO_LINE_BAR ||
			type == GDC_3DCOMBO_HLC_BAR )
			{
			if( uvol[0] != GDC_NOVALUE )
				draw_3d_bar( im, PX(0), PX(0)+hlf_barwdth,
								 PV(0), PV(uvol[0]),
								 0, 0,
								 ExtVolColor[0],
								 ExtVolColor[0] );
			for( i=1; i<num_points-1; ++i )
				if( uvol[i] != GDC_NOVALUE )
					draw_3d_bar( im, PX(i)-hlf_barwdth, PX(i)+hlf_barwdth,
									 PV(0), PV(uvol[i]),
									 0, 0,
									 ExtVolColor[i],
									 ExtVolColor[i] );
			if( uvol[i] != GDC_NOVALUE )
				draw_3d_bar( im, PX(i)-hlf_barwdth, PX(i),
								 PV(0), PV(uvol[i]),
								 0, 0,
								 ExtVolColor[i],
								 ExtVolColor[i] );
			}
		else
		if( type == GDC_COMBO_HLC_AREA   ||
			type == GDC_COMBO_LINE_AREA  ||
			type == GDC_3DCOMBO_LINE_AREA||
			type == GDC_3DCOMBO_HLC_AREA )
			for( i=1; i<num_points; ++i )
				if( uvol[i-1] != GDC_NOVALUE && uvol[i] != GDC_NOVALUE )
					draw_3d_area( im, PX(i-1), PX(i),
									 PV(0), PV(uvol[i-1]), PV(uvol[i]),
									 0, 0,
									 ExtVolColor[i],
									 ExtVolColor[i] );
		setno = 0;
		}		/* volume polys done*/

	if( GDC_annotation && threeD )		/* back half of annotation line */
		{
		int	x1 = PX(GDC_annotation->point+(do_bar?1:0)),
			y1 = PY(lowest);
		setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets:
															   num_sets:
												 1; /* backmost*/
		gdImageLine( im, x1, y1, PX(GDC_annotation->point+(do_bar?1:0)), PY(lowest), AnnoteColor );
		gdImageLine( im, PX(GDC_annotation->point+(do_bar?1:0)), PY(lowest),
						 PX(GDC_annotation->point+(do_bar?1:0)), PY(highest)-2, AnnoteColor );
		setno = 0;
		}

	/* ---------- start plotting the data ---------- */
	switch( type )
		{
		case GDC_3DBAR:					/* depth, width, y interval need to allow for whitespace between bars */
		case GDC_BAR:
		/* --------- */
		switch( GDC_stack_type )
			{
			case GDC_STACK_DEPTH:
			for( setno=num_sets-1; setno>=0; --setno )		/* back sets first   PX, PY depth*/
				for( i=0; i<num_points; ++i )
					if( uvals[setno][i] != GDC_NOVALUE )
						draw_3d_bar( im, PX(i+(do_bar?1:0))-hlf_barwdth, PX(i+(do_bar?1:0))+hlf_barwdth,
										 PY(0), PY(uvals[setno][i]),
										 xdepth_3D, ydepth_3D,
										 ExtColor I(setno,i),
										 threeD? ExtColorShd I(setno,i): ExtColor I(setno,i) );
			setno = 0;
			break;

			case GDC_STACK_LAYER:
				{
				j = 0;
/*				for( i=0; i<num_points; ++i )*/
/*					if( uvals[j][i] != GDC_NOVALUE )*/
/*						{*/
/*						lasty[i] = uvals[j][i];*/
/*						draw_3d_bar( im, PX(i+(do_bar?1:0))-hlf_barwdth, PX(i+(do_bar?1:0))+hlf_barwdth,*/
/*										 PY(0), PY(uvals[j][i]),*/
/*										 xdepth_3D, ydepth_3D,*/
/*										 ExtColor I(j,i),*/
/*										 threeD? ExtColorShd I(j,i): ExtColor I(j,i) );*/
/*						}*/
				for( i=0; i<num_points; ++i )
					{
					struct BS
#ifdef USE_ALLOCA
								*barset =(struct BS*)alloca (num_sets * sizeof (struct BS));
#else
								barset[num_sets];
#endif /* USE_ALLOCA */
					float		lasty_pos = 0.0;
					float		lasty_neg = 0.0;
					int			k;

					for( j=0, k=0; j<num_sets; ++j )
						{
						if( uvals[j][i] != GDC_NOVALUE )
							{
							if( uvals[j][i] < 0.0 )
								{
								barset[k].y1 = lasty_neg;
								barset[k].y2 = uvals[j][i] + lasty_neg;
								lasty_neg    = barset[k].y2;
								}
							else
								{
								barset[k].y1 = lasty_pos;
								barset[k].y2 = uvals[j][i] + lasty_pos;
								lasty_pos    = barset[k].y2;
								}
							barset[k].clr   = ExtColor I(j,i);
							barset[k].shclr = threeD? ExtColorShd I(j,i): ExtColor I(j,i);
							++k;
							}
						}
					qsort( barset, k, sizeof(struct BS), barcmpr );

					for( j=0; j<k; ++j )
						{
						draw_3d_bar( im,
									 PX(i+(do_bar?1:0))-hlf_barwdth, PX(i+(do_bar?1:0))+hlf_barwdth,
									 PY(barset[j].y1), PY(barset[j].y2),
									 xdepth_3D, ydepth_3D,
									 barset[j].clr,
									 barset[j].shclr );
						}
					}
				}
				break;

			case GDC_STACK_BESIDE:
				{												/* h/.5, h/1, h/1.5, h/2, ...*/
				int	new_barwdth = (int)( (float)hlf_barwdth / ((float)num_sets/2.0) );
				for( i=0; i<num_points; ++i )
					for( j=0; j<num_sets; ++j )
						if( uvals[j][i] != GDC_NOVALUE )
							draw_3d_bar( im, PX(i+(do_bar?1:0))-hlf_barwdth+new_barwdth*j+1,
											 PX(i+(do_bar?1:0))-hlf_barwdth+new_barwdth*(j+1),
											 PY(0), PY(uvals[j][i]),
											 xdepth_3D, ydepth_3D,
											 ExtColor I(j,i),
											 threeD? ExtColorShd I(j,i): ExtColor I(j,i) );
					}
				break;
			default:
				break;
			}
			
			break;

		case GDC_LINE:
		case GDC_COMBO_LINE_BAR:
		case GDC_COMBO_LINE_AREA:
			for( j=num_sets-1; j>=0; --j )
				for( i=1; i<num_points; ++i )
					if( uvals[j][i-1] != GDC_NOVALUE && uvals[j][i] != GDC_NOVALUE )
						{
						gdImageLine( im, PX(i-1), PY(uvals[j][i-1]), PX(i), PY(uvals[j][i]), ExtColor I(j,i) );
						gdImageLine( im, PX(i-1), PY(uvals[j][i-1])+1, PX(i), PY(uvals[j][i])+1, ExtColor I(j,i) );
						}
					else
						{
						if( uvals[j][i-1] != GDC_NOVALUE )
							gdImageSetPixel( im, PX(i-1), PY(uvals[j][i-1]), ExtColor I(j,i) );
						if( uvals[j][i] != GDC_NOVALUE )
							gdImageSetPixel( im, PX(i), PY(uvals[j][i]), ExtColor I(j,i) );
						}
			break;

		case GDC_3DLINE:
		case GDC_3DCOMBO_LINE_BAR:
		case GDC_3DCOMBO_LINE_AREA:
			{
			int
#ifdef USE_ALLOCA
				*y1 = (int*)alloca (num_sets * sizeof (int)),
				*y2 = (int*)alloca (num_sets * sizeof (int));
#else
				y1[num_sets],
				y2[num_sets];
#endif /* USE_ALLOCA */

			for( i=1; i<num_points; ++i )
				{
				if( GDC_stack_type == GDC_STACK_DEPTH )
					{
					for( j=num_sets-1; j>=0; --j )
						if( uvals[j][i-1] != GDC_NOVALUE &&
							uvals[j][i]   != GDC_NOVALUE )
							{
							setno = j;
							y1[j] = PY(uvals[j][i-1]);
							y2[j] = PY(uvals[j][i]);

							draw_3d_line( im,
										  PY(0),
										  PX(i-1), PX(i), 
										  &(y1[j]), &(y2[j]),
										  xdepth_3D, ydepth_3D,
										  1,
										  &(ExtColor I(j,i)),
										  &(ExtColorShd I(j,i)) );
							setno = 0;
							}
					}
				else
				if( GDC_stack_type == GDC_STACK_BESIDE ||
					GDC_stack_type == GDC_STACK_SUM )			/* all same plane*/
					{
					int		set;
					int
#ifdef USE_ALLOCA
							*clr = (int*)alloca (num_sets * sizeof (int)),
							*clrshd = (int*)alloca (num_sets * sizeof (int));
#else
							clr[num_sets],
							clrshd[num_sets];
#endif /* USE_ALLOCA */
					float	usey1 = 0.0,
							usey2 = 0.0;
					for( j=0,set=0; j<num_sets; ++j )
						if( uvals[j][i-1] != GDC_NOVALUE &&
							uvals[j][i]   != GDC_NOVALUE )
							{
							if( GDC_stack_type == GDC_STACK_SUM )
								{
								usey1 += uvals[j][i-1];
								usey2 += uvals[j][i];
								}
							else
								{
								usey1 = uvals[j][i-1];
								usey2 = uvals[j][i];
								}
							y1[set]     = PY(usey1);
							y2[set]     = PY(usey2);
							clr[set]    = ExtColor I(j,i);
							clrshd[set] = ExtColorShd I(j,i);	/* fred */
							++set;
							}
					draw_3d_line( im,
						  PY(0),
						  PX(i-1), PX(i), 
						  y1, y2,
						  xdepth_3D, ydepth_3D,
						  set,
						  clr,
						  clrshd );
					}
				}
			}
			break;

		case GDC_AREA:
		case GDC_3DAREA:
		  switch( GDC_stack_type )
			{
			case GDC_STACK_SUM:
				{
				float
#ifdef USE_ALLOCA
						*lasty = (float*)alloca (num_points * sizeof (float));
#else
						lasty[num_points];
#endif /* USE_ALLOCA */
				j = 0;
				for( i=1; i<num_points; ++i )
					if( uvals[j][i] != GDC_NOVALUE )
						{
						lasty[i] = uvals[j][i];
						if( uvals[j][i-1] != GDC_NOVALUE )
							draw_3d_area( im, PX(i-1), PX(i),
											 PY(0), PY(uvals[j][i-1]), PY(uvals[j][i]),
											 xdepth_3D, ydepth_3D,
											 ExtColor I(j,i),
											 threeD? ExtColorShd I(j,i): ExtColor I(j,i) );
						}
				for( j=1; j<num_sets; ++j )
					for( i=1; i<num_points; ++i )
						if( uvals[j][i] != GDC_NOVALUE && uvals[j][i-1] != GDC_NOVALUE )
							{
							draw_3d_area( im, PX(i-1), PX(i),
											 PY(lasty[i]), PY(lasty[i-1]+uvals[j][i-1]), PY(lasty[i]+uvals[j][i]),
											 xdepth_3D, ydepth_3D,
											 ExtColor I(j,i),
                                             threeD? ExtColorShd I(j,i): ExtColor I(j,i) );
							lasty[i] += uvals[j][i];
							}
				}
				break;

			case GDC_STACK_BESIDE:								/* behind w/o depth*/
				for( j=num_sets-1; j>=0; --j )					/* back sets 1st  (setno = 0)*/
					for( i=1; i<num_points; ++i )
						if( uvals[j][i-1] != GDC_NOVALUE && uvals[j][i] != GDC_NOVALUE )
							draw_3d_area( im, PX(i-1), PX(i),
											 PY(0), PY(uvals[j][i-1]), PY(uvals[j][i]),
											 xdepth_3D, ydepth_3D,
											 ExtColor I(j,i),
                                             threeD? ExtColorShd I(j,i): ExtColor I(j,i) );
				break;

			case GDC_STACK_DEPTH:
			default:
				for( setno=num_sets-1; setno>=0; --setno )		/* back sets first   PX, PY depth*/
					for( i=1; i<num_points; ++i )
						if( uvals[setno][i-1] != GDC_NOVALUE && uvals[setno][i] != GDC_NOVALUE )
							draw_3d_area( im, PX(i-1), PX(i),
											 PY(0), PY(uvals[setno][i-1]), PY(uvals[setno][i]),
											 xdepth_3D, ydepth_3D,
											 ExtColor I(setno,i),
                                             threeD? ExtColorShd I(setno,i): ExtColor I(setno,i) );
				setno = 0;
			}
			break;

		case GDC_3DHILOCLOSE:
		case GDC_3DCOMBO_HLC_BAR:
		case GDC_3DCOMBO_HLC_AREA:
			{
			gdPoint     poly[4];
			for( j=num_hlc_sets-1; j>=0; --j )
			 {
			 for( i=1; i<num_points+1; ++i )
				 if( uvals[CLOSESET+j*3][i-1] != GDC_NOVALUE )
					 {
					 if( (GDC_HLC_style & GDC_HLC_I_CAP) &&			/* bottom half of 'I'*/
						 uvals[LOWSET+j*3][i-1] != GDC_NOVALUE )
						 {
						 SET_3D_POLY( poly, PX(i-1)-hlf_hlccapwdth, PX(i-1)+hlf_hlccapwdth,
											PY(uvals[LOWSET+j*3][i-1]), PY(uvals[LOWSET+j*3][i-1]),
											xdepth_3D, ydepth_3D );
						 gdImageFilledPolygon( im, poly, 4, ExtColor I(LOWSET+j*3,i-1) );
						 gdImagePolygon( im, poly, 4, ExtColorShd I(LOWSET+j*3,i-1) );
						 }
																	 /* all HLC have vert line*/
					 if( uvals[LOWSET+j*3][i-1] != GDC_NOVALUE )
						 {											/* bottom 'half'*/
						 SET_3D_POLY( poly, PX(i-1), PX(i-1),
											PY(uvals[LOWSET+j*3][i-1]), PY(uvals[CLOSESET+j*3][i-1]),
											xdepth_3D, ydepth_3D );
						 gdImageFilledPolygon( im, poly, 4, ExtColor I(LOWSET+j*3,i-1) );
						 gdImagePolygon( im, poly, 4, ExtColorShd I(LOWSET+j*3,i-1) );
						 }
					 if( uvals[HIGHSET+j*3][i-1] != GDC_NOVALUE )
						 {											/* top 'half'*/
						 SET_3D_POLY( poly, PX(i-1), PX(i-1),
											PY(uvals[CLOSESET+j*3][i-1]), PY(uvals[HIGHSET+j*3][i-1]),
											xdepth_3D, ydepth_3D );
						 gdImageFilledPolygon( im, poly, 4, ExtColor I(HIGHSET+j*3,i-1) );
						 gdImagePolygon( im, poly, 4, ExtColorShd I(HIGHSET+j*3,i-1) );
						 }
																	/* line at close*/
					 gdImageLine( im, PX(i-1),           PY(uvals[CLOSESET+j*3][i-1]),
									  PX(i-1)+xdepth_3D, PY(uvals[CLOSESET+j*3][i-1])-ydepth_3D,
									  ExtColorShd I(CLOSESET+j*3,i-1) );
																 /* top half 'I'*/
					 if( !( (GDC_HLC_style & GDC_HLC_DIAMOND) &&
							(PY(uvals[HIGHSET+j*3][i-1]) > PY(uvals[CLOSESET+j*3][i-1])-hlf_hlccapwdth) ) &&
						 uvals[HIGHSET+j*3][i-1] != GDC_NOVALUE )
						 if( GDC_HLC_style & GDC_HLC_I_CAP )
							 {
							 SET_3D_POLY( poly, PX(i-1)-hlf_hlccapwdth, PX(i-1)+hlf_hlccapwdth,
												PY(uvals[HIGHSET+j*3][i-1]), PY(uvals[HIGHSET+j*3][i-1]),
												xdepth_3D, ydepth_3D );
							 gdImageFilledPolygon( im, poly, 4, ExtColor I(HIGHSET+j*3,i-1) );
							 gdImagePolygon( im, poly, 4, ExtColorShd I(HIGHSET+j*3,i-1) );
							 }

					 if( i < num_points &&
						 uvals[CLOSESET+j*3][i] != GDC_NOVALUE )
						 {
						 if( GDC_HLC_style & GDC_HLC_CLOSE_CONNECTED )	/* line from prev close */
							 {
							 SET_3D_POLY( poly, PX(i-1), PX(i),
												PY(uvals[CLOSESET+j*3][i-1]), PY(uvals[CLOSESET+j*3][i-1]),
												xdepth_3D, ydepth_3D );
							 gdImageFilledPolygon( im, poly, 4, ExtColor I(CLOSESET+j*3,i) );
							 gdImagePolygon( im, poly, 4, ExtColorShd I(CLOSESET+j*3,i) );
							 }
						 else	/* CLOSE_CONNECTED and CONNECTING are mutually exclusive*/
						 if( GDC_HLC_style & GDC_HLC_CONNECTING )	/* thin connecting line */
							 {
							 int	y1 = PY(uvals[CLOSESET+j*3][i-1]),
								 y2 = PY(uvals[CLOSESET+j*3][i]);
							 draw_3d_line( im,
										   PY(0),
										   PX(i-1), PX(i),
										   &y1, &y2,					/* rem only 1 set*/
										   xdepth_3D, ydepth_3D,
										   1,
										   &(ExtColor I(CLOSESET+j*3,i)),
										   &(ExtColorShd I(CLOSESET+j*3,i)) );
																	 /* edge font of it*/
							 gdImageLine( im, PX(i-1), PY(uvals[CLOSESET+j*3][i-1]),
											  PX(i), PY(uvals[CLOSESET+j*3][i]),
											  ExtColorShd I(CLOSESET+j*3,i) );
							 }
																	 /* top half 'I' again*/
						 if( PY(uvals[CLOSESET+j*3][i-1]) <= PY(uvals[CLOSESET+j*3][i]) &&
							 uvals[HIGHSET+j*3][i-1] != GDC_NOVALUE  )
							 if( GDC_HLC_style & GDC_HLC_I_CAP )
								 {
								 SET_3D_POLY( poly, PX(i-1)-hlf_hlccapwdth, PX(i-1)+hlf_hlccapwdth,
													PY(uvals[HIGHSET+j*3][i-1]), PY(uvals[HIGHSET+j*3][i-1]),
													xdepth_3D, ydepth_3D );
								 gdImageFilledPolygon( im, poly, 4, ExtColor I(HIGHSET+j*3,i-1) );
								 gdImagePolygon( im, poly, 4, ExtColorShd I(HIGHSET+j*3,i-1) );
								 }
						 }
					 if( GDC_HLC_style & GDC_HLC_DIAMOND )
						 {									/* front*/
						 poly[0].x = PX(i-1)-hlf_hlccapwdth;
						  poly[0].y = PY(uvals[CLOSESET+j*3][i-1]);
						 poly[1].x = PX(i-1);
						  poly[1].y = PY(uvals[CLOSESET+j*3][i-1])+hlf_hlccapwdth;
						 poly[2].x = PX(i-1)+hlf_hlccapwdth;
						  poly[2].y = PY(uvals[CLOSESET+j*3][i-1]);
						 poly[3].x = PX(i-1);
						  poly[3].y = PY(uvals[CLOSESET+j*3][i-1])-hlf_hlccapwdth;
						 gdImageFilledPolygon( im, poly, 4, ExtColor I(CLOSESET+j*3,i-1) );
						 gdImagePolygon( im, poly, 4, ExtColorShd I(CLOSESET+j*3,i-1) );
															 /* bottom side*/
						 SET_3D_POLY( poly, PX(i-1), PX(i-1)+hlf_hlccapwdth,
											PY(uvals[CLOSESET+j*3][i-1])+hlf_hlccapwdth,
													 PY(uvals[CLOSESET+j*3][i-1]),
											xdepth_3D, ydepth_3D );
						 gdImageFilledPolygon( im, poly, 4, ExtColorShd I(CLOSESET+j*3,i-1) );
						 /* gdImagePolygon( im, poly, 4, ExtColor I(CLOSESET+j*3,i-1) );*/
															 /* top side*/
						 SET_3D_POLY( poly, PX(i-1), PX(i-1)+hlf_hlccapwdth,
											PY(uvals[CLOSESET+j*3][i-1])-hlf_hlccapwdth,
													 PY(uvals[CLOSESET+j*3][i-1]),
											xdepth_3D, ydepth_3D );
						 gdImageFilledPolygon( im, poly, 4, ExtColor I(CLOSESET+j*3,i-1) );
						 gdImagePolygon( im, poly, 4, ExtColorShd I(CLOSESET+j*3,i-1) );
						 }
					 }
			 }
			}
			break;

		case GDC_HILOCLOSE:
		case GDC_COMBO_HLC_BAR:
		case GDC_COMBO_HLC_AREA:
			for( j=num_hlc_sets-1; j>=0; --j )
				{
				for( i=0; i<num_points; ++i )
					if( uvals[CLOSESET+j*3][i] != GDC_NOVALUE )
						{											/* all HLC have vert line */
						if( uvals[LOWSET+j*3][i] != GDC_NOVALUE )
							gdImageLine( im, PX(i), PY(uvals[CLOSESET+j*3][i]),
											 PX(i), PY(uvals[LOWSET+j*3][i]),
											 ExtColor I(LOWSET+(j*3),i) );
						if( uvals[HIGHSET+j*3][i] != GDC_NOVALUE )
							gdImageLine( im, PX(i), PY(uvals[HIGHSET+j*3][i]),
											 PX(i), PY(uvals[CLOSESET+j*3][i]),
											 ExtColor I(HIGHSET+j*3,i) );

						if( GDC_HLC_style & GDC_HLC_I_CAP )
							{
							if( uvals[LOWSET+j*3][i] != GDC_NOVALUE )
								gdImageLine( im, PX(i)-hlf_hlccapwdth, PY(uvals[LOWSET+j*3][i]),
												 PX(i)+hlf_hlccapwdth, PY(uvals[LOWSET+j*3][i]),
												 ExtColor I(LOWSET+j*3,i) );
							if( uvals[HIGHSET+j*3][i] != GDC_NOVALUE )
								gdImageLine( im, PX(i)-hlf_hlccapwdth, PY(uvals[HIGHSET+j*3][i]),
												 PX(i)+hlf_hlccapwdth, PY(uvals[HIGHSET+j*3][i]),
												 ExtColor I(HIGHSET+j*3,i) );
							}
						if( GDC_HLC_style & GDC_HLC_DIAMOND )
							{
							gdPoint         cd[4];

							cd[0].x = PX(i)-hlf_hlccapwdth;	cd[0].y = PY(uvals[CLOSESET+j*3][i]);
							cd[1].x = PX(i);	cd[1].y = PY(uvals[CLOSESET+j*3][i])+hlf_hlccapwdth;
							cd[2].x = PX(i)+hlf_hlccapwdth;	cd[2].y = PY(uvals[CLOSESET+j*3][i]);
							cd[3].x = PX(i);	cd[3].y = PY(uvals[CLOSESET+j*3][i])-hlf_hlccapwdth;
							gdImageFilledPolygon( im, cd, 4, ExtColor I(CLOSESET+j*3,i) );
							}
						}
				for( i=1; i<num_points; ++i )
					if( uvals[CLOSESET+j*3][i-1] != GDC_NOVALUE && uvals[CLOSESET+j*3][i] != GDC_NOVALUE )
						{
						if( GDC_HLC_style & GDC_HLC_CLOSE_CONNECTED )	/* line from prev close*/
								gdImageLine( im, PX(i-1), PY(uvals[CLOSESET+j*3][i-1]),
												 PX(i), PY(uvals[CLOSESET+j*3][i-1]),
												 ExtColor I(CLOSESET+j*3,i) );
						else	/* CLOSE_CONNECTED and CONNECTING are mutually exclusive*/
						if( GDC_HLC_style & GDC_HLC_CONNECTING )		/* thin connecting line*/
							gdImageLine( im, PX(i-1), PY(uvals[CLOSESET+j*3][i-1]),
											 PX(i), PY(uvals[CLOSESET+j*3][i]),
											 ExtColor I(CLOSESET+j*3,i) );
						}
				}
			break;
		}
		setno = 0;

	/* ---------- scatter points  over all other plots ---------- */
	/* scatters, by their very nature, don't lend themselves to standard array of points */
	/* also, this affords the opportunity to include scatter points onto any type of chart */
	/* drawing of the scatter point should be an exposed function, so the user can */
	/*  use it to draw a legend, and/or add their own */
	if( GDC_scatter )
		{
		int
#ifdef USE_ALLOCA
				*scatter_clr = (int*)alloca (GDC_num_scatter_pts * sizeof (int));
#else
				scatter_clr[GDC_num_scatter_pts];
#endif /* USE_ALLOCA */
		gdPoint	ct[3];

		for( i=0; i<GDC_num_scatter_pts; ++i )
			{
			int		hlf_scatterwdth = (int)( (float)(PX(2)-PX(1))
											 * (((float)((GDC_scatter+i)->width)/100.0)/2.0) );
			int	scat_x = PX( (GDC_scatter+i)->point + (do_bar?1:0) ),
				scat_y = PY( (GDC_scatter+i)->val );

			if( (GDC_scatter+i)->point >= num_points ||				/* invalid point*/
				(GDC_scatter+i)->point <  0 )
				continue;
			scatter_clr[i] = clrallocate( im, (GDC_scatter+i)->color );

			switch( (GDC_scatter+i)->ind )
				{
				case GDC_SCATTER_TRIANGLE_UP:
					ct[0].x = scat_x;
					ct[0].y = scat_y;
					ct[1].x = scat_x - hlf_scatterwdth;
					ct[1].y = scat_y + hlf_scatterwdth;;
					ct[2].x = scat_x + hlf_scatterwdth;
					ct[2].y = scat_y + hlf_scatterwdth;
					if( !do_bar )
						{
						if( (GDC_scatter+i)->point == 0 )
							ct[1].x = scat_x;
						else
						if( (GDC_scatter+i)->point == num_points-1 )
							ct[2].x = scat_x;
						}
					gdImageFilledPolygon( im, ct, 3, scatter_clr[i] );
					break;
				case GDC_SCATTER_TRIANGLE_DOWN:
					ct[0].x = scat_x;
					ct[0].y = scat_y;
					ct[1].x = scat_x - hlf_scatterwdth;
					ct[1].y = scat_y - hlf_scatterwdth;;
					ct[2].x = scat_x + hlf_scatterwdth;
					ct[2].y = scat_y - hlf_scatterwdth;
					if( !do_bar )
						{
						if( (GDC_scatter+i)->point == 0 )
							ct[1].x = scat_x;
						else
						if( (GDC_scatter+i)->point == num_points-1 )
							ct[2].x = scat_x;
						}
					gdImageFilledPolygon( im, ct, 3, scatter_clr[i] );
					break;
				}
			}
		}


/* overlay with a value and an arrow (e.g., total daily change)*/
#ifdef THUMB_VALS
	/* put thmbl and thumbval over vol and plot lines */
	if( thumbnail )
		{
		int     n, d, w;
		char	thmbl[32];
		char	*price_to_str( float, int*, int*, int* );
		char	nmrtr[3+1], dmntr[3+1], whole[8];

		char	*dbg = price_to_str( ABS(thumbval),&n,&d,&w );
		sprintf( nmrtr, "%d", n );
		sprintf( dmntr, "%d", d );
		sprintf( whole, "%d", w );

		gdImageString( im,
					   gdFontSmall,
					   graphwidth/2-strlen(thumblabel)*SFONTWDTH/2,
					   1,
					   thumblabel,
					   ThumbLblColor );
		if( w || n )
			{
			int		chgcolor  = thumbval>0.0? ThumbUColor: ThumbDColor;
			int		thmbvalwidth = SFONTWDTH 					  +	/* up/down arrow*/
								   (w?strlen(whole)*SFONTWDTH: 0) +	/* whole*/
								   (n?strlen(nmrtr)*TFONTWDTH	  +	/* numerator*/
									  SFONTWDTH					  +	
									  strlen(dmntr)*TFONTWDTH:		/* denominator*/
									  0);							/* no frac part*/

			smallarrow( im, graphwidth/2-thmbvalwidth/2, SFONTHGT, thumbval>0.0, chgcolor );
			if( w )
				{
				gdImageString( im,
							   gdFontSmall,
							   (graphwidth/2-thmbvalwidth/2)+SFONTWDTH,
							   SFONTHGT+2,
							   whole,
							   chgcolor );
				}
			if( n )
				{
				gdImageString( im,
							   gdFontTiny,
							   (graphwidth/2-thmbvalwidth/2)   +	/* start*/
							   SFONTWDTH					   +	/* arrow*/
							   (w? strlen(whole)*SFONTWDTH: 0) +	/* whole*/
							   2,
							   SFONTHGT+2-2,
							   nmrtr,
							   chgcolor );
				gdImageChar  ( im,
							   gdFontSmall,
							   (graphwidth/2-thmbvalwidth/2)  +		/* start*/
							   SFONTWDTH					  +		/* arrow*/
							   (w? strlen(whole)*SFONTWDTH: 0) +	/* whole*/
							   strlen(nmrtr)*TFONTWDTH,				/* numerator*/
							   SFONTHGT+2,
							   '/',
							   chgcolor );
				gdImageString( im,
							   gdFontTiny,
							   (graphwidth/2-thmbvalwidth/2)  +		/* start*/
							   SFONTWDTH					  +		/* arrow*/
							   (w? strlen(whole)*SFONTWDTH: 0) +		/* whole*/
							   strlen(nmrtr)*TFONTWDTH		  +		/* numerator*/
							   SFONTWDTH - 3,						/* */
							   SFONTHGT+2+4,
							   dmntr,
							   chgcolor );
				}
			}
		}		/* thumblabel, thumbval*/
#endif

	/* box it off */
	/*  after plotting so the outline covers any plot lines */
	if( GDC_border )
		{
		gdImageLine( im,          PX(0),   PY(lowest), PX(num_points-1+(do_bar?2:0)),  PY(lowest), LineColor );

		setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets: num_sets: 1;
		gdImageLine( im,          PX(0),   PY(highest), PX(num_points-1+(do_bar?2:0)),  PY(highest), LineColor );
		setno = 0;
		}
	if( GDC_border )
		{
		int	x1, y1, x2, y2;

		x1 = PX(0);
		y1 = PY(highest);
		x2 = PX(num_points-1+(do_bar?2:0));
		y2 = PY(lowest);
		gdImageLine( im, x1, PY(lowest), x1, y1, LineColor );

		setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets: num_sets: 1;
		gdImageLine( im, x1, y1, PX(0), PY(highest), LineColor );
		/* if( !GDC_grid || do_vol || GDC_thumbnail )	 */				/* grid leaves right side Y open*/
			{
			gdImageLine( im, x2, y2, PX(num_points-1+(do_bar?2:0)), PY(lowest), LineColor );
			gdImageLine( im, PX(num_points-1+(do_bar?2:0)), PY(lowest),
							 PX(num_points-1+(do_bar?2:0)), PY(highest), LineColor );
			}
		setno = 0;
		}

	if( GDC_0Shelf && threeD &&								/* front of 0 shelf */
		( (lowest < 0.0 && highest > 0.0) ||
		  (lowest < 0.0 && highest > 0.0) ) )
		{
		int	x2 = PX( num_points-1+(do_bar?2:0) ),
			y2 = PY( 0 );

		gdImageLine( im, PX(0), PY(0), x2, y2, LineColor );		/* front line*/
		setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets: num_sets:
												 1;				/* backmost*/
																/* depth for 3Ds*/
		gdImageLine( im, x2, y2, PX(num_points-1+(do_bar?2:0)), PY(0), LineColor );
		setno = 0;												/* set back to foremost*/
		}

	if( GDC_annotation )			/* front half of annotation line */
		{
		int		x1 = PX(GDC_annotation->point+(do_bar?1:0)),
				y1 = PY(highest);
		int		x2;
															/* front line*/
		gdImageLine( im, x1, PY(lowest)+1, x1, y1, AnnoteColor );
		if( threeD )
			{												/* on back plane*/
			setno = GDC_stack_type==GDC_STACK_DEPTH? num_hlc_sets? num_hlc_sets: num_sets: 1;
			x2 = PX(GDC_annotation->point+(do_bar?1:0));
															/* prspective line*/
			gdImageLine( im, x1, y1, x2, PY(highest), AnnoteColor );
			}
		else												/* for 3D done with back line*/
			{
			x2 = PX(GDC_annotation->point+(do_bar?1:0));
			gdImageLine( im, x1, y1, x1, y1-2, AnnoteColor );
			}
		/* line-to and note */
		if( *(GDC_annotation->note) )						/* any note?*/
			{
			if( GDC_annotation->point >= (num_points/2) )		/* note to the left */
				{
				gdImageLine( im, x2,              PY(highest)-2,
								 x2-annote_hgt/2, PY(highest)-2-annote_hgt/2,
								 AnnoteColor );
				GDCImageStringNL( im,
								  &GDC_fontc[GDC_annotation_font],
								  x2-annote_hgt/2-1-annote_len - 1,
								  PY(highest)-annote_hgt+1,
								  GDC_annotation->note,
								  AnnoteColor,
								  GDC_JUSTIFY_RIGHT );
				}
			else												/* note to right */
				{
				gdImageLine( im, x2,              PY(highest)-2,
								 x2+annote_hgt/2, PY(highest)-2-annote_hgt/2,
								 AnnoteColor );
				GDCImageStringNL( im,
								  &GDC_fontc[GDC_annotation_font],
								  x2+annote_hgt/2+1 + 1,
								  PY(highest)-annote_hgt+1,
								  GDC_annotation->note,
								  AnnoteColor,
								  GDC_JUSTIFY_LEFT );
				}
			}
		setno = 0;
		}


	/* usually GDC_generate_gif is used in conjunction with hard or hold options */
	if( GDC_generate_gif )
		{
		fflush(gif_fptr);			/* clear anything buffered */
		gdImageGif( im, gif_fptr );
		}

	if( bg_img )
		gdImageDestroy(bg_img);
	if( GDC_hold_img & GDC_EXPOSE_IMAGE )
		GDC_image = (void*)im;
	else
		gdImageDestroy(im);
	return 0;
}


/* $Id$
 * local variables:
 * mode: c
 * tab-width: 4
 * fill-column: 120
 * end:
 */
