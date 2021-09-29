######sgx_status_t sgx_ocall(const unsigned int index, void *ms)
It checks index of OCALL so that index is within the ocall table range, then it calls __morestack in trs_pic.S.
######__morestack(trs_pic.S)
It saves old rbp and subs rsp by 4*WORDSIZE, then calls do_ocall in trs_pic.S.
######do_ocall(index, ms)
Fistly, it saves xfeature registers, GPRs and other important info, then calls store_xregs and restore_xregs to set values of xregisters, after that it saves value of OCALL_FLAG and ocall_index in stack, then it calls update_ocall_lastsp to save contents of current stack, which can be saved in ecall, Finally it uses value saved in thread_data to restore rbp, rsp， moves ret_addr to rbp, set value of rax to $SE_EEXIT, clears all GPRs and calls ENCLU.
######update_ocall_lastsp(ocall_context_t* context)
It gets current thread_data, then sets pre_last_sp of context to thread_data->last_sp, set thread_data->last_sp to context, this process is an insertion of linked list.
######__morestack(enter_enclave.S)
It compares value of rdi, judging whether reason of returning is OCALL, then calls sgx_ocall, sets function parameters and calls stack_sticker, which is a wrapper of ocall. After returning from stack_sticker, it sets value of xdi to $ECMD_ORET and jumps into .Ldo_eenter. After entering enclave, it calls do_oret to restore value of registers in ecall.
######int stack_sticker(unsigned int proc, sgx_ocall_table_t *ocall_table, void *ms, CTrustThread *trust_thread, tcs_t *tcs)
Firstly, it has the stack 16 bytes aligned, saves old rbp and return adress in stack, save the first 4 parameters, then calls push_ocall_frame, after that it recovers parameters and calls sgx_ocall. After ocall is done, it calls pop_ocall_frame, which is a process of linked list deletion. Finally it calls recovers the return address ,frame_point and return value, leave and return.
######push_ocall_frame(uintptr_t frame_point, tcs_t* tcs, CTrustThread *trust_thread)
It gets the address of enclave, then invokes CEnclave::push_ocall_frame.
######sgx_ocall(const unsigned int proc, const sgx_ocall_table_t *ocall_table, void *ms, CTrustThread *trust_thread)
It gets the address of enclave. then invokes CEnclave::ocall.
######do_oret(void *ms)
It first deletes stack pointer stored in thread data, then invokes asm_oret.
######asm_oret(last_sp, ms);
It first restores thread_data.last_sp, then restore extended feature registers, return value and GPRs, then return to last ecall.
