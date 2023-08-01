#include "TestEnclave_u.h"
#include <errno.h>

typedef struct ms_boot_enclave_t {
	int ms_BF_size;
	int ms_BF_k;
	long int ms_epoch_fraction;
	double ms_delta_fraction;
} ms_boot_enclave_t;

typedef struct ms_generate_user_pseudonyms_t {
	unsigned char* ms_pseudonym;
	size_t ms_PseudoSize;
	int ms_N_pseudonyms;
	unsigned char* ms_outgoingPseudoBuffer;
	size_t ms_OutBufferSize;
} ms_generate_user_pseudonyms_t;

typedef struct ms_generate_user_pseudonyms_orlp_t {
	unsigned char* ms_pseudonym;
	size_t ms_PseudoSize;
	int ms_N_pseudonyms;
	unsigned char* ms_outgoingPseudoBuffer;
	size_t ms_OutBufferSize;
} ms_generate_user_pseudonyms_orlp_t;

typedef struct ms_print_ocall_t {
	const char* ms_string;
} ms_print_ocall_t;

typedef struct ms_printLong_ocall_t {
	long int ms_value;
} ms_printLong_ocall_t;

typedef struct ms_printHexOcall_t {
	const char* ms_str;
	const unsigned char* ms_hash;
	size_t ms_len;
} ms_printHexOcall_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL TestEnclave_print_ocall(void* pms)
{
	ms_print_ocall_t* ms = SGX_CAST(ms_print_ocall_t*, pms);
	print_ocall(ms->ms_string);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_printLong_ocall(void* pms)
{
	ms_printLong_ocall_t* ms = SGX_CAST(ms_printLong_ocall_t*, pms);
	printLong_ocall(ms->ms_value);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_printHexOcall(void* pms)
{
	ms_printHexOcall_t* ms = SGX_CAST(ms_printHexOcall_t*, pms);
	printHexOcall(ms->ms_str, ms->ms_hash, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[12];
} ocall_table_TestEnclave = {
	12,
	{
		(void*)TestEnclave_print_ocall,
		(void*)TestEnclave_printLong_ocall,
		(void*)TestEnclave_printHexOcall,
		(void*)TestEnclave_u_sgxssl_ftime,
		(void*)TestEnclave_sgx_oc_cpuidex,
		(void*)TestEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)TestEnclave_pthread_wait_timeout_ocall,
		(void*)TestEnclave_pthread_create_ocall,
		(void*)TestEnclave_pthread_wakeup_ocall,
	}
};
sgx_status_t boot_enclave(sgx_enclave_id_t eid, int BF_size, int BF_k, long int epoch_fraction, double delta_fraction)
{
	sgx_status_t status;
	ms_boot_enclave_t ms;
	ms.ms_BF_size = BF_size;
	ms.ms_BF_k = BF_k;
	ms.ms_epoch_fraction = epoch_fraction;
	ms.ms_delta_fraction = delta_fraction;
	status = sgx_ecall(eid, 0, &ocall_table_TestEnclave, &ms);
	return status;
}

sgx_status_t generate_user_pseudonyms(sgx_enclave_id_t eid, unsigned char* pseudonym, size_t PseudoSize, int N_pseudonyms, unsigned char* outgoingPseudoBuffer, size_t OutBufferSize)
{
	sgx_status_t status;
	ms_generate_user_pseudonyms_t ms;
	ms.ms_pseudonym = pseudonym;
	ms.ms_PseudoSize = PseudoSize;
	ms.ms_N_pseudonyms = N_pseudonyms;
	ms.ms_outgoingPseudoBuffer = outgoingPseudoBuffer;
	ms.ms_OutBufferSize = OutBufferSize;
	status = sgx_ecall(eid, 1, &ocall_table_TestEnclave, &ms);
	return status;
}

sgx_status_t generate_user_pseudonyms_orlp(sgx_enclave_id_t eid, unsigned char* pseudonym, size_t PseudoSize, int N_pseudonyms, unsigned char* outgoingPseudoBuffer, size_t OutBufferSize)
{
	sgx_status_t status;
	ms_generate_user_pseudonyms_orlp_t ms;
	ms.ms_pseudonym = pseudonym;
	ms.ms_PseudoSize = PseudoSize;
	ms.ms_N_pseudonyms = N_pseudonyms;
	ms.ms_outgoingPseudoBuffer = outgoingPseudoBuffer;
	ms.ms_OutBufferSize = OutBufferSize;
	status = sgx_ecall(eid, 2, &ocall_table_TestEnclave, &ms);
	return status;
}

