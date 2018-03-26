#include "myutils.h"

void gethashforaes(sds hashid, unsigned char hash[]){

	SHA1_CTX ctx;
	SHA1Init(&ctx);
	SHA1Update(&ctx, (const unsigned char*)hashid, strlen(hashid));
	SHA1Update(&ctx, "fsocietyagain", strlen("fsocietyagain"));
	SHA1Final(hash, &ctx);
	sdsfree(hashid);

	return;
}
