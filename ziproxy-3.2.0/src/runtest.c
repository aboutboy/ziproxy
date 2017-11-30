/*
 * runtest.c
 *
 *  Created on: Jun 18, 2012
 *      Author: jiangxd
 */
#include <stdio.h>
#include <stdlib.h>
//#include "googlemap.h"
#include "user_settings.h"
#include "png_compressor.h"
#include "image.h"

int main(int argc, char **argv)
{
	int retval = 0;
//	if (( retval = image_test())) {
//		fprintf(stderr,"image_test failed:%d\n",retval);
//		return retval;
//	}
//	if (( retval = compress_png_test())) {
//		fprintf(stderr,"compress_png_test failed:%d\n",retval);
//		return retval;
//	}
//	if (( retval = log_test())) {
//		fprintf(stderr,"log_test failed:%d\n",retval);
//		return retval;
//	}
//	if (( retval = google_map_test())) {
//		fprintf(stderr,"google_map_test failed:%d\n",retval);
//		return retval;
//	}
//	if (( retval = apple_map_test())) {
//		fprintf(stderr,"apple_map_test failed:%d\n",retval);
//		return retval;
//	}
//	if (( retval = png_compressor_runtests())) {
//		fprintf(stderr,"png_compressor_runtests failed:%d\n",retval);
//		return retval;
//	}
#ifdef USER_SETTINGS
	if ((retval = user_settings_test())) {
		fprintf(stderr, "user_settings_test failed:%d\n", retval);
		return retval;
	}
#endif
	return 0;
}
