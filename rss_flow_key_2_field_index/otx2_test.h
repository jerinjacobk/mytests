#ifndef _OTX2_TESTS_H_
#define _OTX2_TESTS_H_

#define CLNRM  "\x1b[0m"
#define CLRED  "\x1b[31m"
#define CLGRN  "\x1b[32m"
#define CLYEL  "\x1b[33m"

typedef int (*test_fn)(void);
typedef int (*test_fn_args)(void *);

#define OTX2_TEST_NAME_MAX 96

struct otx2_test {
	char name[OTX2_TEST_NAME_MAX];
	int result;
	test_fn fn;
};

int otx2_run_tests(struct otx2_test *tests, int nr_tests);

#define OTX2_TEST(fn) {#fn, 0, fn}
#define OTX2_RUN_TESTS(t) otx2_run_tests(t, sizeof(t)/sizeof(*t))

#define OTX2_DBG printf("%s: %s() %d\n", __FILE__, __func__, __LINE__)
#define OTX2_DBG_RC printf("%s: %s() %d %d\n", __FILE__, __func__, __LINE__, rc)

#endif /* _OTX2_TESTS_H_ */
