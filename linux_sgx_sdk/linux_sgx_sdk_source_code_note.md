## sgx_create_enclave_ex

&emsp;parse and check the elf file(elf header, machine mode, program segment(load segment overlap, dynamic segment), section(symbol table, relocation entries, .ctor sections)), build_regular_sections

&emsp;get_enclave_creator()->use_se_hw() != (!parser.get_symbol_rva("g_global_data_sim"))

&emsp;get_ex_feature_pointer(SGX_CREATE_ENCLAVE_EX_PCL, ex_features, ex_features_p, &ex_fp) judge whether PCL is needed, PCL(Intel® Software Guard Extensions Protected Code Loader)

&emsp;get_meta_data(get urts_version, get_misc_attr)

&emsp;get_misc_attr(get_plat_cap) CPUID instruction (https://www.felixcloutier.com/x86/cpuid)

&emsp;extended inline asm(https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html)

&emsp;set debug flag

&emsp;check xfrm flag in secs, check misc_select

&emsp;Check KSS(Key Separation & Sharing)

&emsp;init_xsave_info() set global variables: g_xsave_size, g_clean_ymm

&emsp;__create_enclave()

&emsp;&emsp;get_ex_feature_pointer(SGX_CREATE_ENCLAVE_EX_KSS)

&emsp;&emsp;load_enclave_ex(load_enclave)

&emsp;&emsp;&emsp;validate_metadata

&emsp;&emsp;&emsp;&emsp;validate_layout_table

&emsp;&emsp;&emsp;&emsp;validate_patch_table

&emsp;&emsp;&emsp;get_misc_attr

&emsp;&emsp;&emsp;build_image

&emsp;&emsp;&emsp;&emsp;build_secs

&emsp;&emsp;&emsp;&emsp;&emsp;create_enclave

&emsp;&emsp;&emsp;&emsp;&emsp;enclave_create

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;get_driver_type

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;mmap

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;mumap

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;ioctl(ECREATE)

&emsp;&emsp;&emsp;&emsp;get_reloc_bitmap

&emsp;&emsp;&emsp;&emsp;patch enclave file

&emsp;&emsp;&emsp;&emsp;build_sections(LOAD segment)

&emsp;&emsp;&emsp;&emsp;&emsp;build_mem_region

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;add_enclave_page

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;enclave_load_data

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;ioctl(EADD)

&emsp;&emsp;&emsp;&emsp;build_contexts(build thread contexts)

&emsp;&emsp;&emsp;&emsp;&emsp;init_enclave

&emsp;&emsp;&emsp;&emsp;&emsp;try_init_enclave	

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;enclave_initialize

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;get_launch_token

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;ioctl(EINIT)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;reg_sig_handler

&emsp;&emsp;CEnclave->initialize

&emsp;&emsp;CEnclave->set_dbg_flag

&emsp;&emsp;CEnclave->get_debug_info

&emsp;&emsp;CEnclave->set_extra_debug_info

&emsp;&emsp;add_enclave(add enclave to Enclave Pool)

&emsp;&emsp;add_thread

&emsp;&emsp;get_enclave_creator()->initialize

&emsp;&emsp;&emsp;do_init_enclave(in enclave)

&emsp;&emsp;&emsp;&emsp;init_enclave(in enclave)

&emsp;&emsp;&emsp;&emsp;&emsp;relocate_enclave(in enclave)

&emsp;&emsp;&emsp;&emsp;&emsp;heap_init(in enclave)

&emsp;&emsp;&emsp;&emsp;&emsp;get_xfeature_state(in enclave)

&emsp;&emsp;&emsp;&emsp;&emsp;init_optimized_libs(in enclave)

&emsp;&emsp;&emsp;&emsp;&emsp;sgx_read_rand(in enclave)

&emsp;&emsp;loader.post_init_action_commit(layout_start, layout_end, 0)

&emsp;&emsp;loader.set_memory_protection()

&emsp;&emsp;get_ex_feature_pointer(SGX_CREATE_ENCLAVE_EX_SWITCHLESS)

&emsp;&emsp;enclave->init_uswitchless(us_config)



## do_ecall

&emsp;get_tcs

&emsp;enter_enclave(__morestack)(tcs, fn, ocall_table, ms, trust_thread)

&emsp;&emsp;EENTER_PROLOG(save GPRs, save extended feature registers)

&emsp;&emsp;ENCLU(EENTER)

&emsp;&emsp;restore_xregs(prepare for SGX enclave)(in enclave)

&emsp;&emsp;enclave_entry(in enclave)

&emsp;&emsp;&emsp;enter_enclave(in enclave)(int index, void \*ms, void \*tcs, int cssa)

&emsp;&emsp;&emsp;&emsp;do_ecall(in enclave)  

&emsp;&emsp;&emsp;&emsp;&emsp;trts_ecall(in enclave)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;get_func_addr(in enclave)

&emsp;&emsp;&emsp;return(in enclave)

&emsp;&emsp;restore_xregs(in enclave)

&emsp;&emsp;ENCLU(EEXIT)(in enclave)

&emsp;&emsp;EENTER_EPILOG



## sgx_ocall(in enclave)

&emsp;do_ocall(in enclave)

&emsp;&emsp;update_ocall_lastsp(in enclave) //thread_data->last_sp is only set when ocall or exception handling 
occurs

&emsp;&emsp;ENCLU(in enclave)

&emsp;&emsp;stack_sticker(ocall_index, ocall_table, ms, trust_thread, tcs)

&emsp;&emsp;&emsp;push_ocall_frame(frame_point, tcs, trust_thread)

&emsp;&emsp;&emsp;sgx_ocall(proc, ocall_table, ms,trust_thread)

&emsp;&emsp;&emsp;&emsp;CEnclave::ocall(const unsigned int proc, const sgx_ocall_table_t \*ocall_table, void \*ms)

&emsp;&emsp;&emsp;pop_ocall_frame

&emsp;&emsp;jmp     .Ldo_eenter

&emsp;&emsp;&emsp;enter_enclave(in enclave)(int index, void \*ms, void \*tcs, int cssa)

&emsp;&emsp;&emsp;&emsp;do_oret(ms)

&emsp;&emsp;&emsp;&emsp;&emsp;asm_oret(last_sp, ms)

sgx_ocfree()



###### SGX Exception Handling(https://github.com/MWShan/linux-sgx/blob/master/docs/DesignDocs/IntelSGXExceptionHandling-Linux.md)

###### restriction of SGX nested exception

###### SGX pthread(https://community.intel.com/t5/Intel-Software-Guard-Extensions/Intel-SGX-Pthreads/m-p/1231185)

###### sgx exception handler register example(https://github.com/deathholes/sgx-enclave-sample/blob/master/Enclave/Enclave.cpp)

###### CFI Directives CFI(Call Frame Information)(https://sourceware.org/binutils/docs/as/CFI-directives.html)

###### CFA(Call Frame Address)https://stackoverflow.com/questions/12977179/reading-living-process-memory-without-interrupting-it

###### rip relative addressing(https://sourceware.org/binutils/docs/as/i386_002dMemory.html)

###### xsave instruction(https://www.felixcloutier.com/x86/xsave)

###### SGX libOS(https://github.com/Liaojinghui/awesome-sgx#LibOS)

###### cpuid instruction(https://www.felixcloutier.com/x86/cpuid)

## SGX2 EDMM(Explicit EPC Allocation):

&emsp;The enclave determines the address at which a new EPC page needs to be committed, and executes ENCLU[EACCEPT]on that address

&emsp;Commit the page containing the #PF

&emsp;keep commiting until existing page is reached, upper bound is reached or it has been aligned

Implicit EPC Allocation:

&emsp;The enclave tries to access a non-existing page "accidentally", and triggers a #PF

&emsp;The SGX driver intercepts the #PF, and commits a page

&emsp;The SGX driver notices at this point that the allocation is implicit, and injects an exception to the 
faulting applications

&emsp;The uRTS handles the exception by making an Ecall to the enclave. This Ecall is made using the same enclave 
Thread Context that faulted

&emsp;The enclave's exception handler supplied by the tRTS handles the exception by accepting the newly committed 
pages, and then exits back.

&emsp;The enclave is resumed and tries the faulting instruction, which will succeed this time.



## Thread Creation:

&emsp;The whole thread context should be declared to the SGX Driver

&emsp;The enclave accepts "Stack Page N"

&emsp;The enclave accepts the rest of the pages

&emsp;The enclave initializes the content of the TCS page

&emsp;The enclave makes an OCall requesting the SGX driver to convert the TCS page to the type of PT_TCS

&emsp;The enclave accepts the page type change using ENCLU[EACCEPT]



###### dlmalloc(http://gee.cs.oswego.edu/dl/html/malloc.html)



## explicit EPC Allocation sbrk(intptr_t n):

&emsp;if(n < 0)

&emsp;&emsp;set start_addr and invokes trim_EPC_pages(start_address, page_count)

&emsp;&emsp;&emsp;check_dynamic_range(check if the addr belongs to dynamic range specified)

&emsp;&emsp;&emsp;trim_range_ocall

&emsp;&emsp;&emsp;&emsp;trim_range(outside enclave)

&emsp;&emsp;&emsp;&emsp;&emsp;iotcl(m_hdevice, SGX_IOC_ENCLAVE_TRIM)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;__modify_range(struct sgx_encl \*encl, struct sgx_range \*rg, struct 
sgx_secinfo *secinfo)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;isolate_range(struct sgx_encl \*encl, struct sgx_range \*rg, struct 
list_head *list) remove page from enclave_load_list and insert it into the trimmed_list

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;__emodt(struct sgx_secinfo \*secinfo, void \*epc)

&emsp;&emsp;&emsp;sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start, end) ENCLU(EACCEPT)

&emsp;&emsp;&emsp;trim_range_commit_ocall(size_t addr)

&emsp;&emsp;&emsp;&emsp;ocall_trim_accept(void\* pms) (outside enclave)

&emsp;&emsp;&emsp;&emsp;&emsp;ioctl(m_hdevice, SGX_IOC_ENCLAVE_NOTIFY_ACCEPT, &params);

&emsp;else

&emsp;&emsp;if(PAGE_DIR_GROW_DOWN)

&emsp;&emsp;&emsp;sgx_accept_forward(SI_FLAG_TRIM | SI_FLAG_MODIFIED, start, end) ENCLU(EACCEPT)

&emsp;&emsp;else

&emsp;&emsp;&emsp;sgx_accept_backward(SI_FLAGS_RW | SI_FLAG_PENDING, start, end)  ENCLU(EACCEPT)



## implicit EPC Allocation(stack expansion):

&emsp;in the first phase, it will check whether sp is smaller than stack_commit_addr, then invokes 
expand_stack_by_pages, which invokes do_accept



## SGX driver source code:

&emsp;sgx_drv_probe(probe whether SGX is supported in CPU)

&emsp;sgx_dev_init

&emsp;&emsp;sgx_xsave_size_tbl

&emsp;&emsp;sgx_add_epc_bank

&emsp;&emsp;sgx_page_cache_init



## sgx page fault handling:

&emsp;sgx_vma_open(struct vm_area_struct \*vma)

&emsp;&emsp;sgx_fault_page(struct vm_area_struct \*vma, unsigned long addr, unsigned int flags, struct vm_fault 
\*vmf)

&emsp;&emsp;&emsp;sgx_do_fault(struct vm_area_struct \*vma, unsigned long addr, unsigned int flags, struct vm_fault 
\*vmf)

&emsp;&emsp;&emsp;&emsp;sgx_encl_augment(struct vm_area_struct \*vma, unsigned long addr, bool write)

&emsp;&emsp;&emsp;&emsp;&emsp;sgx_alloc_page(unsigned int flags)

&emsp;&emsp;&emsp;&emsp;&emsp;sgx_init_page(struct sgx_encl, struct sgx_encl_page, unsigned long, unsigned int, 
struct sgx_epc_page, bool)

&emsp;&emsp;&emsp;&emsp;&emsp;__eaug(struct sgx_pageinfo \*pginfo, void \*epc)

&emsp;&emsp;&emsp;&emsp;&emsp;if(write)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;return ERR_PTR(-EFAULT)

&emsp;&emsp;&emsp;&emsp;&emsp;else

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;return encl_page

if write is specified, SIGBUS is sent to the process, and exception will be invoked



## linux kernel page fault handling:

do_page_fault(struct pt_regs \*regs, unsigned long error_code)

&emsp;__do_page_fault(struct pt_regs \*regs, unsigned long hw_error_code, unsigned long address)

&emsp;&emsp;do_user_addr_fault(regs, hw_error_code, address)

&emsp;&emsp;&emsp;do_user_addr_fault(struct pt_regs \*regs, unsigned long hw_error_code, unsigned long address)

&emsp;&emsp;&emsp;&emsp;__handle_mm_fault(struct vm_area_struct \*vma, unsigned long address, unsigned int flags)

&emsp;&emsp;&emsp;&emsp;&emsp;handle_pte_fault(struct vm_fault \*vmf)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;__do_fault(struct vm_fault \*vmf)



## int pthread_create(pthread_t \*threadp, const pthread_attr_t \*attr, void \*(\*start_routine)(void \*), void \*arg)

&emsp;malloc(sizeof(pthread))

&emsp;SGX_THREAD_QUEUE_INSERT_TAIL(que, elm, lock)

&emsp;pthread_create_ocall(int\* retval, unsigned long long self)

&emsp;&emsp;CTrustThread \* CEnclave::get_free_tcs()(try to get tcs from free_list)(Min/Max number of threads is 
specified in enclave configuration file)

&emsp;&emsp;&emsp;sgx_status_t CTrustThreadPool::new_thread()(make pthread from m_unallocated_threads list)

&emsp;&emsp;&emsp;&emsp;(sgx_status_t)do_ecall(ECMD_MKTCS, octbl, &ms1, m_utility_thread)

&emsp;&emsp;&emsp;&emsp;&emsp;sgx_status_t do_add_thread(void \*ptcs) (in enclave)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;apply_EPC_pages() (in enclave) (to alloc pages for tcs of new thread)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;sgx_ocall(0, tcs) (in enclave) (send MKTCS signal to driver)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;sgx_ioc_page_to_tcs(struct file \*filep, unsigned int cmd, unsigned long 
arg) (in driver)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;__modify_range(struct sgx_encl \*encl, struct sgx_range *rg, struct 
sgx_secinfo \*secinfo) (in driver) (__emodt(secinfo, epc_va))

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;sgx_accept_backward(SI_FLAG_TCS | SI_FLAG_MODIFIED, (size_t)tcs, (size_t)tcs + 
SE_PAGE_SIZE) (in enclave)

&emsp;&emsp;pthread_create(&thread, &attr, pthread_create_routine, (void \*)(trust_thread))

&emsp;&emsp;&emsp;enclave->ecall(ECMD_ECALL_PTHREAD, NULL, (void\*)&waiter, false)

&emsp;&emsp;&emsp;&emsp;sgx_status_t do_init_thread(void \*tcs, bool enclave_init) (in enclave)

&emsp;&emsp;&emsp;&emsp;trts_ecall(uint32_t ordinal, void *ms)

&emsp;&emsp;&emsp;&emsp;&emsp;_pthread_thread_run(void* ms)(execute the thread)

&emsp;int _pthread_wait_timeout(sgx_thread_t waiter_td, uint64_t timeout)(wait until the "start routine" has been 
executed by new created thread)



###### Understanding of linux elf file (https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/)



## sgx_sign

&emsp;cmdline_parse(check mode: sign, gendata, catsig, dump)

&emsp;if(mode == DUMP)

&emsp;&emsp;dump_enclave_metadata

&emsp;else

&emsp;&emsp;parse_metadata_file

&emsp;&emsp;parse_key_file

&emsp;&emsp;copy_file

&emsp;&emsp;measure_enclave

&emsp;&emsp;&emsp;run_parser

&emsp;&emsp;&emsp;build_metadata

&emsp;&emsp;&emsp;&emsp;modify_metadata

&emsp;&emsp;&emsp;&emsp;build_layout_table

&emsp;&emsp;&emsp;&emsp;&emsp;build_guard_page

&emsp;&emsp;&emsp;&emsp;&emsp;build_heap

&emsp;&emsp;&emsp;&emsp;&emsp;build_thread_layout(guard page | stack | guard page | TCS | SSA | guard page | TLS)

&emsp;&emsp;&emsp;&emsp;&emsp;build_utility_thread_context

&emsp;&emsp;&emsp;&emsp;&emsp;adding thread contexts corresponding to tcs_min_pool

&emsp;&emsp;&emsp;&emsp;&emsp;adding thread contexts corresponding to tcs_eremove

&emsp;&emsp;&emsp;&emsp;&emsp;build dynamic thread contexts

&emsp;&emsp;&emsp;&emsp;&emsp;build reserved memory region

&emsp;&emsp;&emsp;&emsp;&emsp;update_layout_entries

&emsp;&emsp;&emsp;&emsp;&emsp;build_tcs_template

&emsp;&emsp;&emsp;&emsp;build_patch_table(patch global data | section header table)

&emsp;&emsp;&emsp;&emsp;&emsp;build_patch_entries

&emsp;&emsp;&emsp;&emsp;build_layout_entries

&emsp;&emsp;&emsp;&emsp;build_gd_template

&emsp;&emsp;&emsp;get_enclave_info

&emsp;&emsp;&emsp;dump_textrels

&emsp;&emsp;&emsp;&emsp;get_executable_sections

&emsp;&emsp;&emsp;&emsp;get_reloc_entry_offset(get relocation entry in executable sections)

&emsp;&emsp;&emsp;load_enclave(load enclave to get enclave hash)

&emsp;&emsp;&emsp;&emsp;Measuring ECREATE EADD

&emsp;&emsp;&emsp;get_enclave_creator()->get_enclave_info

&emsp;&emsp;generate_output

&emsp;&emsp;&emsp;fill_enclave_css

&emsp;&emsp;&emsp;create_signature

&emsp;&emsp;verify_signature

&emsp;&emsp;generate_compatible_metadata

&emsp;&emsp;update_metadata



## get_launch_token

&emsp;oal_get_launch_token

&emsp;&emsp;AEServicesProvider::GetServicesProvider

&emsp;&emsp;servicesProvider->InternalInterface

&emsp;&emsp;&emsp;mTransporter->transact(request, response, timeout_msec)

&emsp;&emsp;&emsp;&emsp;sendMessage(reqMsg, communicationSocket)

&emsp;&emsp;&emsp;&emsp;receiveMessage(communicationSocket)



## aesm_service(directory of log.txt: /var/opt/aesmd/data)

&emsp;aesmLogic->service_start()

&emsp;&emsp;service->start()

&emsp;&emsp;&emsp;CLEClass::instance().load_enclave()

&emsp;&emsp;&emsp;&emsp;CLEClass::load_enclave_only()

&emsp;&emsp;&emsp;&emsp;&emsp;aesm_get_pathname(FT_PERSISTENT_STORAGE, LE_PROD_SIG_STRUCT_FID, prod_css_path, 
MAX_PATH) le_prod_css.bin

&emsp;&emsp;&emsp;&emsp;&emsp;aesm_get_pathname(FT_ENCLAVE_NAME, get_enclave_fid(), enclave_path, MAX_PATH) 
libsgx_le.signed.so

&emsp;&emsp;&emsp;&emsp;sgx_create_le

&emsp;&emsp;&emsp;&emsp;init_get_launch_token(::get_launch_token)

&emsp;&emsp;&emsp;&emsp;&emsp;get_launch_token_internal(enclave_hash, signature_key.modulus, launch_token)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;sgx_ecall

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;le_generate_launch_token(const sgx_measurement_t* mrenclave, const 
sgx_measurement_t* mrsigner, const sgx_attributes_t* se_attributes, token_t* lictoken)

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;sgx_create_report // Create report to get current cpu_svn and 
isv_svn

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;do_ereport

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;le_calc_lic_token

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;sgx_get_key

&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;sgx_cmac128_init sgx_cmac128_update sgx_cmac128_final



## TCS_bind_policy has two kinds, bind(bind TCS to a thread) and unbind 

SGX_Switchless_calls:

sl_init_uswitchless:

&emsp;sl_uswitchless_new

&emsp;&emsp;check_switchless_params

&emsp;&emsp;sl_call_mngr_init（SL_TYPE_OCALL, SL_TYPE_ECALL）

&emsp;&emsp;&emsp;sl_siglines_init()

&emsp;&emsp;sl_workers_init(SL_WORKER_TYPE_UNTRUSTED,SL_WORKER_TYPE_TRUSTED)

&emsp;sl_uswitchless_init_workers(uswitchless_p)

&emsp;&emsp;sl_workers_init_threads(&handle->us_uworkers)

&emsp;&emsp;&emsp;pthread_create(run_worker)

&emsp;&emsp;&emsp;&emsp;sl_workers_notify_event(workers, SL_WORKER_EVENT_START)

&emsp;&emsp;&emsp;&emsp;sleep_this_thread()

&emsp;&emsp;&emsp;&emsp;process_calls_fn/ continue to sleep



## tworker_process_calls:

&emsp;sl_run_switchless_tworker

&emsp;&emsp;sl_call_once

&emsp;&emsp;sl_call_mngr_process

&emsp;&emsp;&emsp;sl_siglines_process_signals



SGX Launch Enclave: Get EINITTOKEN
SGX Provision Enclave:Get Provision key and Attestation Key
SGX Quoting Enclave: Get Attestation key and replace MAC in the report



the last page in tls is used to store thread data



## mutex:

sgx_thread_mutex_lock:

&emsp;SPIN_LOCK(&mutex->m_lock)

&emsp;check whether queue in mutex is empty

&emsp;SPIN_UNLOCK(&mutex->m_lock)

&emsp;sgx_thread_wait_untrusted_event_ocall

&emsp;&emsp;se_event_wait(outside enclave)



## sgx_thread_mutex_unlock:

&emsp;sgx_thread_mutex_unlock_lazy(get the first thread which should be waken up)

&emsp;&emsp;sgx_thread_set_untrusted_event_ocall(&ret, TD2TCS(waiter))

&emsp;&emsp;&emsp;se_event_wake(outside enclave)



## 用户进程注册的异常处理函数执行流程：

Linux内核会将一个非阻塞的信号发送给该进程。当中断或异常发生时，进程切换到内核态。正要返回用户态前，内核执行do_signal()函数，这个函数又依次处理信号(通过调用handle_signal())和建立用户态堆栈(通过调用setup_frame()或setup_rt_frame())。当进程又切换到用户态时，因为信号处理程序的起始地址被强制放进程序计数器中，因此开始执行信号处理程序，当处理程序终止时，setup_frame()或setup_rt_frame()函数放在用户态的返回代码就被执行。这个代码调用sigreturn()或rt_sigreturn()系统调用，相应的服务例程把正常程序的用户态堆栈硬件上下文拷贝到内核态堆栈，并把用户态堆栈恢复到它原来的状态。系统调用结束时，普通进程就可以恢复自己的执行。