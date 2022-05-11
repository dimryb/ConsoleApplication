
#include "adapter.h"
#include "mbedtls/include/mbedtls/rsa.h"
#include <stdio.h>
#include "rsaTest.h"

void adapter() {
	int verbose = 1;
	int result = mbedtls_rsa_self_test(verbose);

	result = rsa_test(verbose);
}

int (*mbedtls_snprintf)(char* s, size_t n, const char* format, ...) = snprintf;
