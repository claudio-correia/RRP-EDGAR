#ifndef TESTENCLAVE_T_H__
#define TESTENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void boot_enclave(int BF_size, int BF_k, long int epoch_fraction, double delta_fraction);
void generate_user_pseudonyms(unsigned char* pseudonym, size_t PseudoSize, int N_pseudonyms, unsigned char* outgoingPseudoBuffer, size_t OutBufferSize);
void generate_user_pseudonyms_orlp(unsigned char* pseudonym, size_t PseudoSize, int N_pseudonyms, unsigned char* outgoingPseudoBuffer, size_t OutBufferSize);

sgx_status_t SGX_CDECL print_ocall(const char* string);
sgx_status_t SGX_CDECL printLong_ocall(long int value);
sgx_status_t SGX_CDECL printHexOcall(const char* str, const unsigned char* hash, size_t len);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
