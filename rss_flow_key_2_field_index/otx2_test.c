#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "otx2_test.h"

int
otx2_run_tests(struct otx2_test *tests, int nr_tests)
{
	const char *str_success = "Success";
	const char *str_fail = "Fail";
	int failed = 0;
	int i;

	for (i = 0; i < nr_tests; i++) {
		struct otx2_test *test = tests + i;

		test->result = test->fn();
		if (test->result) {
			++failed;
			printf("\t[%d]%-*s:"CLRED"%s"CLNRM" rc=%d\n", i,
			OTX2_TEST_NAME_MAX, test->name, str_fail, test->result);
		} else {
			printf("\t[%d]%-*s:"CLGRN"%s"CLNRM"\n", i,
			OTX2_TEST_NAME_MAX, test->name, str_success);
		}
	}
	if (failed)
		printf("\t"CLRED"%d tests failed (%d/%d)"CLNRM"\n",
				failed, failed, nr_tests);
	else
		printf("\t"CLGRN"All tests passed (%d/%d)"CLNRM"\n",
				nr_tests, nr_tests);
	return failed;
}

