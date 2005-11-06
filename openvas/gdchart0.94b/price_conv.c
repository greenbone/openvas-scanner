/* GDCHART 0.94b  PRICE_CONV.C  12 Nov 1998 */

/* 
*  - price as float to a string (ostensibly for printing)
*/

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>

/* ----------------------------------------------------------------- */
/* -- convert a float to a printable string, in form:             -- */
/* --	W N/D                                                     -- */
/* -- where W is whole, N is numerator, D is denominator          -- */
/* -- the frac N/D is one of 2nds, 4,8,16,32,64,128,256ths        -- */
/* -- if cannot convert, return str of the float                  -- */
/* ----------------------------------------------------------------- */

#define EPSILON		((1.0/256.0)/2.0)
#define GET_DEC(x)	( (x) - (float)(int)(x) )

char*
price_to_str( float	price,
			  int	*numorator,
			  int	*demoninator,
			  int	*decimal,
			  char	*fltfmt )			/* printf fmt'ing str*/
{
    static char rtn[64];
	int			whole = (int)price;
	float		dec   = GET_DEC( price ),
				numr;
	/* float		pow( double, double ); */

	/* caller doesn't want fractions*/
	if( fltfmt )
		{
		sprintf( rtn, fltfmt, price );
		*numorator = *demoninator = *decimal = 0;
		return rtn;
		}

	numr = dec * 256;
	/* check if we have a perfect fration in 256ths */
	{	
		float	rdec = GET_DEC( numr );

		if( rdec < EPSILON )
			;							/* close enough to frac */
		else if( (1-rdec) < EPSILON )	/* just over but close enough */
			++numr;
		else							/* no frac match */
		{
			sprintf( rtn, "%f", price );
			*numorator = *demoninator = *decimal = 0;
			return rtn;
		}
	}

	/* now have numr 256ths */
	/* resolve down */
	if( numr != 0 )
		{
		int	cnt = 8;

		while( (float)(numr)/2.0 == (float)(int)(numr/2) )
			{
			numr /= 2;
			--cnt;
			}

		/* don't want both whole AND numerator to be - */
		if( whole<0 && numr<0.0 )
			numr = -numr;
		*numorator = (int)numr;
		*demoninator = (int)pow(2.0, (float)cnt);
		*decimal = whole;
		sprintf( rtn, "%d %d/%d", whole,
								  (int)numr,
								  *demoninator );
		}
	else
		{
		*numorator = *demoninator = 0;
		*decimal = whole;
		sprintf( rtn, "%d", whole );
		}

    return rtn;
}

