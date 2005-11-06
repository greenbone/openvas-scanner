/* GDCHART 0.94b  GDC_PIE.C  12 Nov 1998 */

#include <includes.h>

#ifdef HAVE_FLOAT_H
#include <float.h>
#endif

#define GDC_INCL
#define GDC_LIB
#define GDC_VARS
#include "gdc.h"
#include "gdcpie.h"

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

#ifndef MAXFLOAT
# define MAXFLOAT FLT_MAX
#endif

/* rem circle:  x = rcos(@), y = rsin(@)	*/

extern struct	GDC_FONT_T	GDC_fontc[];

#define SET_RECT( gdp, x1, x2, y1, y2 )	gdp[0].x = gdp[3].x = x1,	\
					gdp[0].y = gdp[1].y = y1,	\
					gdp[1].x = gdp[2].x = x2,	\
					gdp[2].y = gdp[3].y = y2

#define PX( x )				( cx + (int)( ((float)rad)*sin(pscl*(double)(x)) ) )		/* expects a val */
#define PY( x )				( cy - (int)( ((float)rad)*cos(pscl*(double)(x)) ) )		/* expects a val */

#define CX( i,d )		( cx                +	\
						  (d? xdepth_3D: 0) +	\
						  (int)( (double)(GDCPIE_explode?GDCPIE_explode[(i)]:0) * sin((double)(slice_angle I(0,i))) ) )
#define CY( i,d )		( cy                -	\
						  (d? ydepth_3D: 0) -	\
						  (int)( (double)(GDCPIE_explode?GDCPIE_explode[(i)]:0) * cos((double)(slice_angle I(0,i))) ) )
/* expect slice number:     i (index into slice_angle array) *\ 
 *   and position on slice: f (0: slice middle,              *
 *                             1: leading (clockwise),       *
 *                             2: trailing edge)             *
 *   and 3D depth:          d (0: do depth,                  *
 *                             1: no depth adjustment)       *
\* adjusts for explosion                                     */
#define IX( i,f,d )		( CX(i,d) + (int)( (double)rad * sin((double)(slice_angle I(f,i))) ) )
#define IY( i,f,d )		( CY(i,d) - (int)( (double)rad * cos((double)(slice_angle I(f,i))) ) )
/* same as above except o is angle */
#define OX( i,o,d )		( CX(i,d) + (int)( (double)rad * sin((double)(o)) ) )
#define OY( i,o,d )		( CY(i,d) - (int)( (double)rad * cos((double)(o)) ) )

#ifndef HAVE_RINT
#define rint(x)             (int)((x) + 0.5)
#endif

#define TO_INT_DEG(o)		(int)rint( (double)((o)/(2.0*M_PI)*360.0) )
#define TO_INT_DEG_FLOOR(o)	(int)floor( (double)((o)/(2.0*M_PI)*360.0) )
#define TO_INT_DEG_CEIL(o)	(int)ceil( (double)((o)/(2.0*M_PI)*360.0) )
#define TO_RAD(o)			( (o)/360.0*(2.0*M_PI) )
																					/* assume !> 4*PI */
#define MOD_2PI(o)			( (o)>=(2.0*M_PI)? ((o)-(2.0*M_PI)): (((o)<0)? ((o)+(2.0*M_PI)): (o)) )
#define MOD_360(o)			( (o)>=360? (o)-360: (o) )								/* assume !> 720 */ 

struct tmp_slice_t { int	i;					/* original index*/
					 char	hidden;				/* 'behind' top [3D] pie*/
					 float	angle;				/* radian */
					 float	slice; };			/* radian*/
static float				pie_3D_rad;			/* user requested 3D angle in radians*/

/* degrees (radians) between angle a, and depth angle*/
/* 1&2, so comparisons can be done.*/
#define RAD_DIST1( a )		( (dist_foo1=ABS(((a>-.00001&&a<.00001)?0.00001:a)-pie_3D_rad)), ((dist_foo1>M_PI)? ABS(dist_foo1-2.0*M_PI): dist_foo1) )
#define RAD_DIST2( a )		( (dist_foo2=ABS(((a>-.00001&&a<.00001)?0.00001:a)-pie_3D_rad)), ((dist_foo2>M_PI)? ABS(dist_foo2-2.0*M_PI): dist_foo2) )
static float				dist_foo1, dist_foo2;

/* ------------------------------------------------------- *\ 
 * oof!  cleaner way???
 * order by angle opposite (180) of depth angle
 * comparing across 0-360 line
\* ------------------------------------------------------- */
static int ocmpr( struct tmp_slice_t *a, struct tmp_slice_t *b )
{
	if( RAD_DIST1(a->angle) < RAD_DIST2(b->angle) )
		return 1;
	if( RAD_DIST1(a->angle) > RAD_DIST2(b->angle) )
		return -1;

	/* a tie (will happen between each slice) */
	/* are we within pie_3D_rad */
	if( ((a->angle < pie_3D_rad) && (pie_3D_rad < a->slice)) ||
		((a->slice < pie_3D_rad) && (pie_3D_rad < a->angle)) )
		return 1;
	if( ((b->slice < pie_3D_rad) && (pie_3D_rad < b->angle)) ||
		((b->angle < pie_3D_rad) && (pie_3D_rad < b->slice)) )
		return -1;

	/* let slice angle decide */
	if( RAD_DIST1(a->slice) < RAD_DIST2(b->slice) )
		return 1;
	if( RAD_DIST1(a->slice) > RAD_DIST2(b->slice) )
		return -1;

	return 0;
}

/* ======================================================= *\ 
 * PIE
 * 
 * Notes:
 *  always drawn from 12:00 position clockwise
 *  'missing' slices don't get labels
 *  sum(val[0], ... val[num_points-1]) is assumed to be 100%
\* ======================================================= */
void
pie_gif( short			GIFWIDTH,
		 short			GIFHEIGHT,
		 FILE			*gif_fptr,			/* open file pointer */
		 GDCPIE_TYPE	type,
		 int			num_points,
		 char			*lbl[],				/* data labels */
		 float			val[] )				/* data */
{
	int			i;

	gdImagePtr	im;
	int			BGColor,
				LineColor,
				PlotColor,
				EdgeColor = 0,
				EdgeColorShd = 0,
#ifdef USE_ALLOCA
				*SliceColor = (int*)alloca (num_points * sizeof (int)),
				*SliceColorShd = (int*)alloca (num_points * sizeof (int));
#else
				SliceColor[num_points],
				SliceColorShd[num_points];
#endif /* USE_ALLOCA */
	float		rad = 0.0;					/* radius*/
	float		tot_val = 0.0;
	float		pscl;
	int			cx,							/* affects PX()*/
				cy;							/* affects PY()*/
								/* ~ 1% for a size of 100 pixs */
								/* label sizes will more dictate this */
	float		min_grphable = ( GDCPIE_other_threshold < 0?
								  100.0/(float)MIN(GIFWIDTH,GIFHEIGHT):
								  (float)GDCPIE_other_threshold )/100.0;
#ifdef USE_ALLOCA
	char		*others = (char*)alloca (num_points);
	float		*slice_angle = (float*)alloca (3 * num_points * sizeof (float));
#else
	char		others[num_points];
	float		slice_angle[3][num_points];	/* must be used with others[]*/
#endif /* USE_ALLOCA */
	char		threeD = ( type == GDC_3DPIE );

	int			xdepth_3D      = 0,			/* affects PX()*/
				ydepth_3D      = 0;			/* affects PY()*/
			 						/* reserved for macro use*/

/*	GDCPIE_3d_angle = MOD_360(90-GDCPIE_3d_angle+360);*/
	pie_3D_rad = TO_RAD( GDCPIE_3d_angle );

	xdepth_3D      = threeD? (int)( cos((double)MOD_2PI(M_PI_2-pie_3D_rad+2.0*M_PI)) * GDCPIE_3d_depth ): 0;
	ydepth_3D      = threeD? (int)( sin((double)MOD_2PI(M_PI_2-pie_3D_rad+2.0*M_PI)) * GDCPIE_3d_depth ): 0;
/*	xdepth_3D      = threeD? (int)( cos(pie_3D_rad) * GDCPIE_3d_depth ): 0;*/
/*	ydepth_3D      = threeD? (int)( sin(pie_3D_rad) * GDCPIE_3d_depth ): 0;*/

	load_font_conversions();

	/* ----- get total value ----- */
	for( i=0; i<num_points; ++i )
		tot_val += val[i];

	/* ----- pie sizing ----- */
	/* ----- make width room for labels, depth, etc.: ----- */
	/* ----- determine pie's radius ----- */
	{
	int		title_hgt  = GDCPIE_title? 1			/*  title? horizontal text line */
									   + GDC_fontc[GDCPIE_title_size].h
										* (int)cnt_nl( GDCPIE_title, (int*)NULL )
									   + 2:
									   0;
	float	last = 0.0;
	int		cheight,
			cwidth;

	/* maximum: no labels, explosions*/
	/* gotta start somewhere*/
	rad = (float)MIN( GIFWIDTH/2-(1+ABS(xdepth_3D)), GIFHEIGHT/2-(1+ABS(ydepth_3D))-title_hgt );

	/* ok fix center, i.e., no floating re labels, explosion, etc. */
	cx = GIFWIDTH/2 /* - xdepth_3D */ ;
	cy = (GIFHEIGHT-title_hgt)/2 + title_hgt /* + ydepth_3D */ ;

	cheight = (GIFHEIGHT- title_hgt)/2 /* - ydepth_3D */ ;
	cwidth  = cx;

	/* walk around pie. determine spacing to edge */
	for( i=0; i<num_points; ++i )
		{
		float	this_pct = val[i]/tot_val;						/* should never be > 100% */
		float	this = this_pct*(2.0*M_PI);						/* pie-portion */
		if( (this_pct > min_grphable) ||						/* too small */
			(!GDCPIE_missing || !GDCPIE_missing[i]) )			/* still want angles */
			{
			int this_explode = GDCPIE_explode? GDCPIE_explode[i]: 0;
			double	this_sin;
			double	this_cos;
			slice_angle I(0,i) = this/2.0+last;				/* mid-point on full pie */
			slice_angle I(1,i) = last;						/* 1st on full pie */
			slice_angle I(2,i) = this+last;					/* 2nd on full pie */
			this_sin        = sin( (double)slice_angle I(0,i) );
			this_cos        = cos( (double)slice_angle I(0,i) );

			if( !GDCPIE_missing || !(GDCPIE_missing[i]) )
				{
				short	lbl_wdth,
						lbl_hgt;
				float	this_y_explode_limit,
						this_x_explode_limit;

				/* start slice label height, width     */
				/*  accounting for PCT placement, font */
				if( lbl && lbl[i] )
					{
					char	foo[1+4+1+1];					/* XPG2 compatibility */
					int		pct_len;
					int		lbl_len = 0;
					lbl_hgt = ( cnt_nl(lbl[i], &lbl_len) + (GDCPIE_percent_labels == GDCPIE_PCT_ABOVE ||
															GDCPIE_percent_labels == GDCPIE_PCT_BELOW? 1: 0) )
							  * (GDC_fontc[GDCPIE_label_size].h+1);
					sprintf( foo,
							 (GDCPIE_percent_labels==GDCPIE_PCT_LEFT ||
							  GDCPIE_percent_labels==GDCPIE_PCT_RIGHT) &&
							 lbl[i]? "(%.0f%%)":
									 "%.0f%%",
							this_pct * 100.0 );
					pct_len = GDCPIE_percent_labels == GDCPIE_PCT_NONE? 0: strlen(foo);
					lbl_wdth = ( GDCPIE_percent_labels == GDCPIE_PCT_RIGHT ||
								 GDCPIE_percent_labels == GDCPIE_PCT_LEFT? lbl_len+1+pct_len:
																		   MAX(lbl_len,pct_len) )
							   * GDC_fontc[GDCPIE_label_size].w;
					}
				else
					lbl_wdth = lbl_hgt = 0;
				/* end label height, width */
				
				/* diamiter limited by this piont's: explosion, label                 */
				/* (radius to box @ slice_angle) - (explode) - (projected label size) */
				/* radius constraint due to labels */
				this_y_explode_limit = (float)this_cos==0.0? MAXFLOAT:
										(	(float)( (double)cheight/ABS(this_cos) ) - 
											(float)( this_explode + (lbl[i]? GDCPIE_label_dist: 0) ) -
											(float)( lbl_hgt/2 ) / (float)ABS(this_cos)	);
				this_x_explode_limit = (float)this_sin==0.0? MAXFLOAT:
										(	(float)( (double)cwidth/ABS(this_sin) ) - 
											(float)( this_explode + (lbl[i]? GDCPIE_label_dist: 0) ) -
											(float)( lbl_wdth ) / (float)ABS(this_sin)	);

				rad = MIN( rad, this_y_explode_limit );
				rad = MIN( rad, this_x_explode_limit );
#if 0
				/* ok at this radius (which is most likely larger than final)*/
				/* adjust for inter-label spacing*/
/*				if( lbl[i] && *lbl[i] )*/
/*					{*/
//					char which_edge = slice_angle[0][i] > M_PI? +1: -1;		/* which semi*/
//					last_label_yedge = cheight - (int)( (rad +				/* top or bottom of label*/
/*														(float)(this_explode +*/
/*														(float)GDCPIE_label_dist)) * (float)this_cos ) +*/
/*											     ( (GDC_fontc[GDCPIE_label_size].h+1)/2 +*/
/*													GDC_label_spacing )*which_edge;*/
/*					}*/
#endif
				/* radius constriant due to exploded depth */
				/* at each edge of the slice, and the middle */
				/* this is really stupid */
				/*  this section uses a different algorithm then above, but does the same thing */
				/*  could be combined, but each is ugly enough! */
/* PROTECT /0*/
				if( threeD )
					{
					short	j;
					int		this_y_explode_pos;
					int		this_x_explode_pos;

					/* first N E S W (actually no need for N)*/
					if( (slice_angle I(1,i) < M_PI_2 && M_PI_2 < slice_angle I(2,i)) &&				/* E*/
						(this_x_explode_pos=OX(i,M_PI_2,1)) > cx+cwidth )
						rad -= (float)ABS( (double)(1+this_x_explode_pos-(cx+cwidth))/sin(M_PI_2) );
					if( (slice_angle I(1,i) < 3.0*M_PI_2 && 3.0*M_PI_2 < slice_angle I(2,i)) &&		/* W*/
						(this_x_explode_pos=OX(i,3.0*M_PI_2,1)) < cx-cwidth )
						rad -= (float)ABS( (double)(this_x_explode_pos-(cx+cwidth))/sin(3.0*M_PI_2) );
					if( (slice_angle I(1,i) < M_PI && M_PI < slice_angle I(2,i)) &&					/* S*/
						(this_y_explode_pos=OY(i,M_PI,1)) > cy+cheight )
						rad -= (float)ABS( (double)(1+this_y_explode_pos-(cy+cheight))/cos(M_PI) );

					for( j=0; j<3; ++j )
						{
						this_y_explode_pos = IY(i,j,1);
						if( this_y_explode_pos < cy-cheight )
							rad -= (float)ABS( (double)((cy-cheight)-this_y_explode_pos)/cos((double)slice_angle I(j,i)) );
						if( this_y_explode_pos > cy+cheight )
							rad -= (float)ABS( (double)(1+this_y_explode_pos-(cy+cheight))/cos((double)slice_angle I(j,i)) );

						this_x_explode_pos = IX(i,j,1);
						if( this_x_explode_pos < cx-cwidth )
							rad -= (float)ABS( (double)((cx-cwidth)-this_x_explode_pos)/sin((double)slice_angle I(j,i)) );
						if( this_x_explode_pos > cx+cwidth )
							rad -= (float)ABS( (double)(1+this_x_explode_pos-(cx+cwidth))/sin((double)slice_angle I(j,i)) );
						}
					}
				}
			others[i] = FALSE;
			}
		else
			{
			others[i] = TRUE;
			slice_angle I(0,i) = -MAXFLOAT;
			}
		last += this;
		}
	}

	/* ----- go ahead and start the GIF ----- */
	im = gdImageCreate( GIFWIDTH, GIFHEIGHT );

	/* --- allocate the requested colors --- */
	BGColor   = clrallocate( im, GDCPIE_BGColor );
	LineColor = clrallocate( im, GDCPIE_LineColor );
	PlotColor = clrallocate( im, GDCPIE_PlotColor );
	if( GDCPIE_EdgeColor != GDC_NOCOLOR )
	 {
	 EdgeColor = clrallocate( im, GDCPIE_EdgeColor );
	 if( threeD )
	  EdgeColorShd = clrshdallocate( im, GDCPIE_EdgeColor );
	 }

	/* --- set color for each slice --- */
	for( i=0; i<num_points; ++i )
		if( GDCPIE_Color )
			{
			unsigned long	slc_clr = GDCPIE_Color[i];

			SliceColor[i]     = clrallocate( im, slc_clr );
			if( threeD )
			 SliceColorShd[i] = clrshdallocate( im, slc_clr );
			}
		else
			{
			SliceColor[i]     = PlotColor;
			if( threeD )
			 SliceColorShd[i] = clrshdallocate( im, GDCPIE_PlotColor );
			}

	pscl = (2.0*M_PI)/tot_val;
	
	/* ----- calc: smallest a slice can be ----- */
	/* 1/2 circum / num slices per side. */
	/*              determined by number of labels that'll fit (height) */
	/* scale to user values */
	/* ( M_PI / (GIFHEIGHT / (SFONTHGT+1)) ) */
/*	min_grphable = tot_val */
/*				   ( 2.0 * (float)GIFHEIGHT / (float)(SFONTHGT+1+TFONTHGT+2) );*/


	if( threeD )
		{
		/* draw background shaded pie */
		{
		float	_rad1 = rad;  /* _WIN32 does not like rad1, using _rad1, instead (jordan) */
		for( i=0; i<num_points; ++i )
			if( !(others[i]) &&
				(!GDCPIE_missing || !GDCPIE_missing[i]) )
				{
				float	rad = _rad1;

				gdImageLine( im, CX(i,1), CY(i,1), IX(i,1,1), IY(i,1,1), SliceColorShd[i] );
				gdImageLine( im, CX(i,1), CY(i,1), IX(i,2,1), IY(i,2,1), SliceColorShd[i] );

				gdImageArc( im, CX(i,1), CY(i,1),
								rad*2, rad*2,
								TO_INT_DEG_FLOOR(slice_angle I(1,i))+270,
								TO_INT_DEG_CEIL(slice_angle I(2,i))+270,
								SliceColorShd[i] );
				_rad1 = rad;
				rad *= 3.0/4.0;
				gdImageFillToBorder( im, IX(i,0,1), IY(i,0,1), SliceColorShd[i], SliceColorShd[i] );
				rad = _rad1;
				if( GDCPIE_EdgeColor != GDC_NOCOLOR )
					{
					gdImageLine( im, CX(i,1), CY(i,1), IX(i,1,1), IY(i,1,1), EdgeColorShd );
					gdImageLine( im, CX(i,1), CY(i,1), IX(i,2,1), IY(i,2,1), EdgeColorShd );
					gdImageArc( im, CX(i,1), CY(i,1), 
									rad*2, rad*2,
									TO_INT_DEG(slice_angle I(1,i))+270, TO_INT_DEG(slice_angle I(2,i))+270,
									EdgeColorShd);
					}
				}
		}
		/* fill in connection to foreground pie */
		/* this is where we earn our keep */
		{
		struct tmp_slice_t	
#ifdef USE_ALLOCA
							*tmp_slice = (struct tmp_slice_t*)alloca ((2*num_points+2) * sizeof (struct tmp_slice_t));
#else
							tmp_slice[2*num_points+2];
#endif
		int					t,
							num_slice_angles = 0;

		for( i=0; i<num_points; ++i )
			if( !GDCPIE_missing || !GDCPIE_missing[i] )
				{
				if( RAD_DIST1(slice_angle I(1,i)) < RAD_DIST2(slice_angle I(0,i)) )
					tmp_slice[num_slice_angles].hidden = FALSE;
				else
					tmp_slice[num_slice_angles].hidden = TRUE;
				tmp_slice[num_slice_angles].i       = i;
				tmp_slice[num_slice_angles].slice   = slice_angle I(0,i);
				tmp_slice[num_slice_angles++].angle = slice_angle I(1,i);
				if( RAD_DIST1(slice_angle I(2,i)) < RAD_DIST2(slice_angle I(0,i)) )
					tmp_slice[num_slice_angles].hidden = FALSE;
				else
					tmp_slice[num_slice_angles].hidden = TRUE;
				tmp_slice[num_slice_angles].i       = i;
				tmp_slice[num_slice_angles].slice   = slice_angle I(0,i);
				tmp_slice[num_slice_angles++].angle = slice_angle I(2,i);
				/* identify which 2 slices (i) have a tangent parallel to depth angle */
				if( slice_angle I(1,i)<MOD_2PI(pie_3D_rad+M_PI_2) && slice_angle I(2,i)>MOD_2PI(pie_3D_rad+M_PI_2) )
					{
					tmp_slice[num_slice_angles].i       = i;
					tmp_slice[num_slice_angles].hidden  = FALSE;
					tmp_slice[num_slice_angles].slice   = slice_angle I(0,i);
					tmp_slice[num_slice_angles++].angle = MOD_2PI( pie_3D_rad+M_PI_2 );
					}

				if( slice_angle I(1,i)<MOD_2PI(pie_3D_rad+3.0*M_PI_2) && slice_angle I(2,i)>MOD_2PI(pie_3D_rad+3.0*M_PI_2) )
					{
					tmp_slice[num_slice_angles].i       = i;
					tmp_slice[num_slice_angles].hidden  = FALSE;
					tmp_slice[num_slice_angles].slice   = slice_angle I(0,i);
					tmp_slice[num_slice_angles++].angle = MOD_2PI( pie_3D_rad+3.0*M_PI_2 );
					}
				}

		qsort( tmp_slice, num_slice_angles, sizeof(struct tmp_slice_t), (int(*)(const void*,const void*))ocmpr);
		for( t=0; t<num_slice_angles; ++t )
			{
			gdPoint	gdp[4];

			i = tmp_slice[t].i;

			gdp[0].x  = CX(i,0);					gdp[0].y = CY(i,0);
			gdp[1].x  = CX(i,1);					gdp[1].y = CY(i,1);
			gdp[2].x  = OX(i,tmp_slice[t].angle,1);	gdp[2].y = OY(i,tmp_slice[t].angle,1);
			gdp[3].x  = OX(i,tmp_slice[t].angle,0);	gdp[3].y = OY(i,tmp_slice[t].angle,0);

			if( !(tmp_slice[t].hidden) )
				gdImageFilledPolygon( im, gdp, 4, SliceColorShd[i] );
			else
				{
				rad -= 2.0;										/* no peeking */
				gdp[0].x  = OX(i,slice_angle I(0,i),0);	gdp[0].y = OY(i,slice_angle I(0,i),0);
				gdp[1].x  = OX(i,slice_angle I(0,i),1);	gdp[1].y = OY(i,slice_angle I(0,i),1);
				rad += 2.0;
				gdp[2].x  = OX(i,slice_angle I(1,i),1);	gdp[2].y = OY(i,slice_angle I(1,i),1);
				gdp[3].x  = OX(i,slice_angle I(1,i),0);	gdp[3].y = OY(i,slice_angle I(1,i),0);
				gdImageFilledPolygon( im, gdp, 4, SliceColorShd[i] );
				gdp[2].x  = OX(i,slice_angle I(2,i),1);	gdp[2].y = OY(i,slice_angle I(2,i),1);
				gdp[3].x  = OX(i,slice_angle I(2,i),0);	gdp[3].y = OY(i,slice_angle I(2,i),0);
				gdImageFilledPolygon( im, gdp, 4, SliceColorShd[i] );
				}
				

			if( GDCPIE_EdgeColor != GDC_NOCOLOR )
				{
				gdImageLine( im, CX(i,0), CY(i,0), CX(i,1), CY(i,1), EdgeColorShd );
				gdImageLine( im, OX(i,tmp_slice[t].angle,0), OY(i,tmp_slice[t].angle,0),
								 OX(i,tmp_slice[t].angle,1), OY(i,tmp_slice[t].angle,1),
							 EdgeColorShd );
				}
			}
		}
		}


	/* ----- pie face ----- */
	{
	/* float	last = 0.0;*/
	  float	_rad1 = rad; /* _WIN32 does not like rad1, using _rad1, instead (jordan) */
	for( i=0; i<num_points; ++i )
		if( !others[i] &&
			(!GDCPIE_missing || !GDCPIE_missing[i]) )
			{
			float	rad = _rad1;

			/* last += val[i];*/
			/* EXPLODE_CX_CY( slice_angle[0][i], i );*/
			gdImageLine( im, CX(i,0), CY(i,0), IX(i,1,0), IY(i,1,0), SliceColor[i] );
			gdImageLine( im, CX(i,0), CY(i,0), IX(i,2,0), IY(i,2,0), SliceColor[i] );

			gdImageArc( im, CX(i,0), CY(i,0), 
							(int)rad*2, (int)rad*2,
							TO_INT_DEG_FLOOR(slice_angle I(1,i))+270,
							TO_INT_DEG_CEIL(slice_angle I(2,i))+270,
							SliceColor[i] );
			_rad1 = rad;
			rad *= 3.0/4.0;
			gdImageFillToBorder( im, IX(i,0,0), IY(i,0,0), SliceColor[i], SliceColor[i] );
			/* catch missed pixels on narrow slices */
			gdImageLine( im, CX(i,0), CY(i,0), IX(i,0,0), IY(i,0,0), SliceColor[i] );
			rad = _rad1;
			if( GDCPIE_EdgeColor != GDC_NOCOLOR )
				{
				gdImageLine( im, CX(i,0), CY(i,0), IX(i,1,0), IY(i,1,0), EdgeColor );
				gdImageLine( im, CX(i,0), CY(i,0), IX(i,2,0), IY(i,2,0), EdgeColor );

				gdImageArc( im, CX(i,0), CY(i,0), 
								rad*2, rad*2,
								TO_INT_DEG(slice_angle I(1,i))+270, TO_INT_DEG(slice_angle I(2,i))+270,
								EdgeColor );
				}
			}
	}

	if( GDCPIE_title )
		{
		int	title_len;

		cnt_nl( GDCPIE_title, &title_len );
		GDCImageStringNL( im,
						  &GDC_fontc[GDCPIE_title_size],
						  (GIFWIDTH-title_len*GDC_fontc[GDCPIE_title_size].w)/2,
						  1,
						  GDCPIE_title,
						  LineColor,
						  GDC_JUSTIFY_CENTER );
		}

	/* labels */
	if( lbl )
		{
		float	liner = rad;

		rad += GDCPIE_label_dist;
		for( i=0; i<num_points; ++i )
			{
			if( !others[i] &&
				(!GDCPIE_missing || !GDCPIE_missing[i]) )
				{
				char	pct_str[1+4+1+1];
				int		pct_wdth;
				int		lbl_wdth;
				short	num_nl = cnt_nl( lbl[i], &lbl_wdth );
				int		lblx,  pctx,
						lbly,  pcty = 0,
						linex, liney;

				lbl_wdth *= GDC_fontc[GDCPIE_label_size].w;
				sprintf( pct_str,
						 (GDCPIE_percent_labels==GDCPIE_PCT_LEFT ||
						  GDCPIE_percent_labels==GDCPIE_PCT_RIGHT) &&
						 lbl[i]? "(%.0f%%)":
								 "%.0f%%",
						(val[i]/tot_val) * 100.0 );
				pct_wdth = GDCPIE_percent_labels == GDCPIE_PCT_NONE?
							0:
							strlen(pct_str) * GDC_fontc[GDCPIE_label_size].w;

				lbly = (liney = IY(i,0,0))-( num_nl * (1+GDC_fontc[GDCPIE_label_size].h) ) / 2;
				lblx = pctx = linex = IX(i,0,0);

				if( slice_angle I(0,i) > M_PI )								/* which semicircle */
					{
					lblx -= lbl_wdth;
					pctx = lblx;
					++linex;
					}
				else
					--linex;

				switch( GDCPIE_percent_labels )
					{
					case GDCPIE_PCT_LEFT:	if( slice_angle I(0,i) > M_PI )
												pctx -= lbl_wdth-1;
											else
												lblx += pct_wdth+1;
											pcty = IY(i,0,0) - ( 1+GDC_fontc[GDCPIE_label_size].h ) / 2;
											break;
					case GDCPIE_PCT_RIGHT:	if( slice_angle I(0,i) > M_PI )
												lblx -= pct_wdth-1;
											else
												pctx += lbl_wdth+1;
											pcty = IY(i,0,0) - ( 1+GDC_fontc[GDCPIE_label_size].h ) / 2;
											break;
					case GDCPIE_PCT_ABOVE:	lbly += (1+GDC_fontc[GDCPIE_label_size].h) / 2;
											pcty = lbly - (GDC_fontc[GDCPIE_label_size].h);
											break;
					case GDCPIE_PCT_BELOW:	lbly -= (1+GDC_fontc[GDCPIE_label_size].h) / 2;
											pcty = lbly + (GDC_fontc[GDCPIE_label_size].h) * num_nl;
											break;
					case GDCPIE_PCT_NONE:
					default:
					  ; /* needed for _WIN32 !! */
					}

				if( GDCPIE_percent_labels != GDCPIE_PCT_NONE )
					gdImageString( im,
								   GDC_fontc[GDCPIE_label_size].f,
								   slice_angle I(0,i) <= M_PI? pctx:
															  pctx+lbl_wdth-pct_wdth,
								   pcty,
								   (u_char*)pct_str,
								   LineColor );
				if( lbl[i] )
					GDCImageStringNL( im,
									  &GDC_fontc[GDCPIE_label_size],
									  lblx,
									  lbly,
									  lbl[i],
									  LineColor,
									  slice_angle I(0,i) <= M_PI? GDC_JUSTIFY_LEFT:
																 GDC_JUSTIFY_RIGHT );
				if( GDCPIE_label_line )
					{
					float	rad = liner;
					gdImageLine( im, linex, liney, IX(i,0,0), IY(i,0,0), LineColor );
					}
				}
			}
		rad -= GDCPIE_label_dist;
		}

	gdImageGif(im, gif_fptr);

	gdImageDestroy(im);
	return;
}

/* $Id$
 * local variables:
 * mode: c
 * tab-width: 4
 * fill-column: 120
 * end:
 */
