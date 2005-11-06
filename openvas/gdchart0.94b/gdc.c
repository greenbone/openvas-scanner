/* GDCHART 0.94b  GDC.C  12 Nov 1998 */

#define GDC_INCL
#define GDC_LIB
#include "includes.h"
#include "gdc.h"

struct	GDC_FONT_T	GDC_fontc[GDC_numfonts] = { 					   {(gdFontPtr)NULL, 8,  5},
											   {(gdFontPtr)NULL, 8,  5},
											   {(gdFontPtr)NULL, 12, 6},
											   {(gdFontPtr)NULL, 13, 7},
											   {(gdFontPtr)NULL, 16, 8},
											   {(gdFontPtr)NULL, 15, 9 }};

/* ------------------------------------------------------------------- *\ 
 * convert from enum GDC_font_size to gd fonts
 * for now load them all
 *	#defines and #ifdefs might enable loading only needed fonts
\* ------------------------------------------------------------------- */
void
load_font_conversions()
{
	GDC_fontc[GDC_pad].f     = gdFontTiny;
	GDC_fontc[GDC_TINY].f    = gdFontTiny;
	GDC_fontc[GDC_SMALL].f   = gdFontSmall;
	GDC_fontc[GDC_MEDBOLD].f = gdFontMediumBold;
	GDC_fontc[GDC_LARGE].f   = gdFontLarge;
	GDC_fontc[GDC_GIANT].f   = gdFontGiant;
}

/* ------------------------------------------------------------------ *\ 
 * count (natural) substrings (new line sep)
\* ------------------------------------------------------------------ */
short
cnt_nl( char	*nstr,
		int		*len )			/* strlen - max seg */
{
	short	c           = 1;
	short	max_seg_len = 0;
	short	tmplen      = 0;

	if( !nstr )
		{
		if( len )
			*len = 0;
		return 0;
		}

	while( *nstr )
		{
		if( *nstr == '\n' )
			{
			++c;
			max_seg_len = MAX( tmplen, max_seg_len );
			tmplen = 0;
			}
		else
			++tmplen;
		++nstr;
		}

	if( len )
		*len = MAX( tmplen, max_seg_len );		/* don't forget last seg */
	return c;
}

/* ------------------------------------------------------------------ *\ 
 * gd out a string with '\n's
\* ------------------------------------------------------------------ */
void
GDCImageStringNL( gdImagePtr		im,
				  struct GDC_FONT_T	*f,
				  int				x,
				  int				y,
				  char				*str,
				  int				clr,
				  GDC_justify_t		justify )
{
	int		i;
	int		len;
	int     max_len;
	short   strs_num = cnt_nl( str, &max_len );
#ifdef _WIN32
#ifdef HAVE__ALLOCA
	char   *sub_str = _alloca (max_len+1);
#else
	char   *sub_str = alloca (max_len+1);
#endif
#else
#ifdef HAVE_ALLOCA
	char   *sub_str = (char*)alloca (max_len+1);
#else
	char    sub_str[max_len+1];
#endif
#endif

	len      = -1;
	strs_num = -1;
	i = -1;
	do
		{
		++i;
		++len;
		sub_str[len] = *(str+i);
		if( *(str+i) == '\n' ||
			*(str+i) == '\0' )
			{
			int	xpos;

			sub_str[len] = '\0';
			++strs_num;
			switch( justify )
			  {
			  case GDC_JUSTIFY_LEFT:	xpos = x;					 break;
			  case GDC_JUSTIFY_RIGHT:	xpos = x+f->w*(max_len-len); break;
			  case GDC_JUSTIFY_CENTER:
			  default:					xpos = x+f->w*(max_len-len)/2;
			  }
			gdImageString( im,
						   f->f,
						   xpos,
						   y + (f->h-1)*strs_num,
						   (u_char*)sub_str,
						   clr );
			len = -1;
			}
		}
	while( *(str+i) );
}

/* ------------------------------------------------------------------------ */
void
GDC_destroy_image(void *im)
{
	if( im )
		gdImageDestroy( (gdImagePtr)im );
}

/* ------------------------------------------------------------------------ */
void
out_err( int			GIFWIDTH,
		 int			GIFHEIGHT,
		 FILE			*fptr,
		 unsigned long	BGColor,
		 unsigned long	LineColor,
		 char			*err_str )
{

	gdImagePtr	im;
	int			lineclr;
	int			bgclr;


	if( (GDC_hold_img & GDC_REUSE_IMAGE) &&
		GDC_image != (void*)NULL )
		im = GDC_image;
	else
		im = gdImageCreate( GIFWIDTH, GIFHEIGHT );

	bgclr    = gdImageColorAllocate( im, l2gdcal(BGColor) );
	lineclr  = gdImageColorAllocate( im, l2gdcal(LineColor) );

	gdImageString( im,
				   gdFontMediumBold,
				   GIFWIDTH/2 - GDC_fontc[GDC_MEDBOLD].w*strlen(err_str)/2,
				   GIFHEIGHT/3,
				   (u_char*)err_str,
				   lineclr );

	/* usually GDC_generate_gif is used in conjunction with hard or hold options */
	if( GDC_generate_gif )
		{
		fflush(fptr);			/* clear anything buffered */
		gdImageGif(im, fptr);
		}

	if( GDC_hold_img & GDC_EXPOSE_IMAGE )
		GDC_image = (void*)im;
	else
		gdImageDestroy(im);
	return;
}
