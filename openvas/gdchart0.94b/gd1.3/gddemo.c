#include <stdio.h>
#include "gd.h"
#include "gdfontg.h"
#include "gdfonts.h"

int main(void)
{
	/* Input and output files */
	FILE *in;
	FILE *out;

	/* Input and output images */
	gdImagePtr im_in, im_out;

	/* Brush image */
	gdImagePtr brush;

	/* Color indexes */
	int white;
	int blue;
	int red;
	int green;

	/* Points for polygon */
	gdPoint points[3];

	/* Create output image, 128 by 128 pixels. */
	im_out = gdImageCreate(128, 128);

	/* First color allocated is background. */
	white = gdImageColorAllocate(im_out, 255, 255, 255);

	/* Set transparent color. */
	gdImageColorTransparent(im_out, white);

	/* Try to load demoin.gif and paste part of it into the
		output image. */

	in = fopen("demoin.gif", "rb");
	if (!in) {
		fprintf(stderr, "Can't load source image; this demo\n");
		fprintf(stderr, "is much more impressive if demoin.gif\n");
		fprintf(stderr, "is available.\n");
		im_in = 0;
	} else {
		im_in = gdImageCreateFromGif(in);
		fclose(in);
		/* Now copy, and magnify as we do so */
		gdImageCopyResized(im_out, im_in, 
			16, 16, 0, 0, 96, 96, 127, 127);		
	}
	red = gdImageColorAllocate(im_out, 255, 0, 0);
	green = gdImageColorAllocate(im_out, 0, 255, 0);
	blue = gdImageColorAllocate(im_out, 0, 0, 255);
	/* Rectangle */
	gdImageLine(im_out, 8, 8, 120, 8, green);	
	gdImageLine(im_out, 120, 8, 120, 120, green);	
	gdImageLine(im_out, 120, 120, 8, 120, green);	
	gdImageLine(im_out, 8, 120, 8, 8, green);	
	/* Circle */
	gdImageArc(im_out, 64, 64, 30, 10, 0, 360, blue);
	/* Arc */
	gdImageArc(im_out, 64, 64, 20, 20, 45, 135, blue);
	/* Flood fill */
	gdImageFill(im_out, 4, 4, blue);
	/* Polygon */
	points[0].x = 32;
	points[0].y = 0;
	points[1].x = 0;
	points[1].y = 64;	
	points[2].x = 64;
	points[2].y = 64;	
	gdImageFilledPolygon(im_out, points, 3, green);
	/* Brush. A fairly wild example also involving a line style! */
	if (im_in) {
		int style[8];
		brush = gdImageCreate(8, 8);
		gdImageCopyResized(brush, im_in,
			0, 0, 0, 0, 
			gdImageSX(brush), gdImageSY(brush),
			gdImageSX(im_in), gdImageSY(im_in));
		gdImageSetBrush(im_out, brush);	
		/* With a style, so they won't overprint each other.
			Normally, they would, yielding a fat-brush effect. */
		style[0] = 0;
		style[1] = 0;
		style[2] = 0;
		style[3] = 0;
		style[4] = 0;
		style[5] = 0;
		style[6] = 0;
		style[7] = 1;
		gdImageSetStyle(im_out, style, 8);
		/* Draw the styled, brushed line */
		gdImageLine(im_out, 0, 127, 127, 0, gdStyledBrushed);
	}
	/* Text */
	gdImageString(im_out, gdFontGiant, 16, 16, "hi", red);
	gdImageStringUp(im_out, gdFontSmall, 32, 32, "hi", red);
	/* Make output image interlaced (allows "fade in" in some viewers,
		and in the latest web browsers) */
	gdImageInterlace(im_out, 1);
	out = fopen("demoout.gif", "wb");
	/* Write GIF */
	gdImageGif(im_out, out);
	fclose(out);
	gdImageDestroy(im_out);
	if (im_in) {
		gdImageDestroy(im_in);
	}
	return 0;
}

