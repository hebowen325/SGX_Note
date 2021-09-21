#linux_sgx_driver介绍
本文主要是希望从几个维度来介绍linux_sgx_driver，也希望能涵盖linux_sgx_driver的全部代码
##sgx_module的init与clean up
sgx_dev_init
&emsp;cpuid_count(get misc attributes and EPC physical size)
&emsp;sgx_add_epc_bank(lower bit in EPC is used to store the number of bank)
&emsp;sgx_page_cache_init
&emsp;&emsp;kthread_run(ksgxswapd)
&emsp;&emsp;&emsp;sgx_isolate_tgid_ctx
&emsp;&emsp;&emsp;sgx_isolate_encl
&emsp;&emsp;&emsp;sgx_isolate_pages
&emsp;&emsp;&emsp;sgx_write_pages(EBLOCK、ETRACK、EWB)
&emsp;&emsp;&emsp;&emsp;sgx_eblock
&emsp;&emsp;&emsp;&emsp;sgx_etrack
&emsp;&emsp;&emsp;&emsp;sgx_evict_page
&emsp;&emsp;&emsp;&emsp;&emsp;sgx_ewb
&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;sgx_get_backing
&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;__ewb
&emsp;&emsp;&emsp;&emsp;&emsp;sgx_free_page
&emsp;alloc_workqueue

&emsp;sgx_drv_remove
&emsp;&emsp;destroy_workqueue(sgx_add_page_wq)
&emsp;&emsp;sgx_page_cache_teardown
&emsp;&emsp;&emsp;kthread_stop(ksgxswapd_tsk);

##sgx enclave creation
sgx_ioc_enclave_create
&emsp;sgx_encl_create
&emsp;&emsp;sgx_encl_alloc
&emsp;&emsp;&emsp;sgx_calc_ssaframesize
&emsp;&emsp;&emsp;shmem_file_setup(set up shared memory for backing and pcmd)
&emsp;&emsp;&emsp;set up related variable
&emsp;&emsp;sgx_alloc_page
&emsp;&emsp;&emsp;sgx_alloc_page_fast
&emsp;&emsp;sgx_add_to_tgid_ctx
&emsp;&emsp;&emsp;sgx_find_tgid_ctx
&emsp;&emsp;sgx_init_page(set up va page)
&emsp;&emsp;&emsp;get va_page offset
&emsp;&emsp;&emsp;sgx_get_page
&emsp;&emsp;&emsp;__epa(add version array)
&emsp;&emsp;sgx_get_page(get kernel address for secs)
&emsp;&emsp;__ecreate
&emsp;&emsp;mmu_notifier_register
&emsp;&emsp;list_add_tail(&encl->encl_list, &encl->tgid_ctx->encl_list);

##sgx enclave add page
sgx_ioc_enclave_add_page
&emsp;sgx_get_encl
&emsp;alloc_page
&emsp;sgx_encl_add_page
&emsp;&emsp;__sgx_encl_add_page
&emsp;&emsp;&emsp;sgx_validate_secinfo
&emsp;&emsp;&emsp;sgx_validate_tcs
&emsp;&emsp;&emsp;sgx_init_page
&emsp;&emsp;&emsp;sgx_get_backing
&emsp;&emsp;&emsp;radix_tree_insert
&emsp;&emsp;&emsp;list_add_tail(&req->list, &encl->add_page_reqs)

sgx_add_page_worker
&emsp;sgx_alloc_page
&emsp;&emsp;sgx_process_add_page_req
&emsp;&emsp;&emsp;sgx_encl_find
&emsp;&emsp;&emsp;sgx_get_backing
&emsp;&emsp;&emsp;sgx_vm_insert_pfn
&emsp;&emsp;&emsp;sgx_eadd
&emsp;&emsp;&emsp;sgx_measure
&emsp;&emsp;&emsp;&emsp;__eextend(get measurement used in software attestation)
&emsp;&emsp;&emsp;&emsp;sgx_test_and_clear_young(encl_page, encl);

##sgx enclave init
sgx_ioc_enclave_init
&emsp;sgx_get_encl
&emsp;sgx_encl_init
&emsp;&emsp;__einit(check measurement of enclave and signer, attributes, misc_select, mac of token, set SECS as initialized)
sigstruct is equal to css

##sgx enclave page permission restriction
sgx_ioc_page_modpr
&emsp;sgx_get_encl
&emsp;__modify_range
&emsp;&emsp;isolate_range(remove pages from load list and insert into remove list)
&emsp;&emsp;sgx_get_page
&emsp;&emsp;__emodpr
&emsp;&emsp;sgx_etrack
&emsp;&emsp;smp_call_function
&emsp;&emsp;list_splice

##sgx enclave page type change
sgx_ioc_page_to_tcs(the same to sgx_ioc_page_modpr)
&emsp;modify_range

##sgx enclave free page
sgx_ioc_trim_page(the same to sgx_ioc_page_to_tcs)
&emsp;modify_range

after those trimmed pages being eaccepted in enclave, pages defined in range will be removed to the trimmed list, and they can be freely removed now

sgx_ioc_page_notify_accept
&emsp;sgx_get_encl
&emsp;remove_page
&emsp;&emsp;sgx_encl_find
&emsp;&emsp;sgx_fault_page
&emsp;&emsp;radix_tree_delete
&emsp;&emsp;zap_vma_ptes
&emsp;&emsp;sgx_free_page

## sgx enclave page remove
sgx_ioc_page_remove
&emsp;remove_page(same to sgx enclave free page)

##page fault attack
为了复现page-fault-attack，我们需要将所有想要观测的页全部置为缺页状态，放置在Func_address数组中。具体步骤如下：
1.在sgx_ioc_enclave_init函数中，调用自行编写的sgx_delete_pte函数，调用zap_vma_ptes函数删除页表中我们所有想要观测的页表项，并插入encl->malicious_delete_tree。
2.在页错误处理函数sgx_vma_fault()中，如果上一次页错误恢复的页为我们想要观测的页，则继续删除该页相关的页表项，即插入encl->malicious_delete_tree。如果该次页错误相关的页表项为我们想要观测的页，则恢复其页表项，从encl->malicious_delete_tree中删除，并记录在encl->last_deleted_page_addr中。
在sgx_encl数据结构中添加的三项数据为struct radix_tree_root malicious_delete_page_tree; bool EINIT_DELETE; unsigned long last_deleted_page_addr; unsigned long start_page_addr;

##Other Note:
因为在代码中大量使用了kref_get与kref_put函数，这里简单记录一下struct kref结构体：
struct kref结构体是一个引用计数器，被嵌套入其他结构体，用来记录这个结构体被引用的次数，使用这个结构体之前必须调用kref_init()函数对这个结构体进行初始化,kref结构体的使用规则具体如下:
1.如果创建一个结构指针的非暂时性副本，这个参数将传递到其他参数或者线程的时候，调用kref_get()
2.当线程使用完这个参数时，必须执行kref_put，如果这是这个结构指针的最后一个引用，release()函数必须被调用
3.如果代码试图在还没有计数的情况下就调用kref_get()，必须串行化kref_put()与kref_get()的执行，防止调用kref_get之前，结构体已经被销毁。
具体见link(https://www.cnblogs.com/Cqlismy/p/11389898.html)

SECS.ATTRIBUTES.XFRM is used to store the processor extended state configuration
SECS.MISC currently is used to store exception information that occurred inside the enclave