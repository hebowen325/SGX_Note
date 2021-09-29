ENCLS Instruction | RAX | RBX | RCX | RDX | Description |
--- | --- | --- | --- | --- | --- |
EADD(SGX1) | 01H | Address of a PAGEINFO | Address of the destination EPC page |  | The leaf function copies a source page from non-enclave memory into the EPC |
EAUG(SGX2) | 0DH | Address of a SECINFO | Address of the destination EPC page |  | The leaf function zeroes a page of EPC memory, associates the EPC page with an SECS page residing in the EPC |
EBLOCK(SGX1) | 09H |  | Effective address of the EPC page |  | This leaf function causes an EPC page to be marked as BLOCKED |
ECREATE(SGX1) | 00H | Address of a PAGEINFO | Address of the destination SECS page |  | ECREATE copies an SECS structure outside the EPC into an SECS page inside the EPC |
EDBGRD(SGX1) | 04H | Data read from a debug enclave(Out) | Address of source memory in the EPC |  | This leaf function copies a quadword/doubleword from an EPC page belonging to a debug enclave into the RBX register |
EDBGWR(SGX1) | 05H | Data to be written to a debug enclave(In) | Address of Target memory in the EPC(In) |   | This leaf function copies the content in EBX/RBX to an EPC page belonging to a debug enclave | 
EEXTEND(SGX1) | 06H |  | Effective address of a 256-byte chunk in the EPC|  | This leaf function updates the MRENCLAVE measurement register of an SECS with the measurement of an EXTEND string compromising of "EEXTEND" \|\| ENCLAVEOFFSET \|\| PADDING \|\| 256 bytes of the enclave page |
EINIT(SGX1) | 02H | Address of SIGSTRUCT | Address of SECS | Address of EINITTOKEN | This leaf function initializes the enclave and makes it ready to execute enclave code | 
ELDB/ELDU(SGX1) | 07H/08H | Address of the PAGEINFO | Address of the EPC page | Address of the version-array slot |This leaf function loads, verifies an EPC page and marks the page as blocked/unblocked |
EMODPR(SGX2) | 0EH | Address of a SECINFO | Address of the destination EPC page |   | This leaf function restricts the access rights associated with an EPC page in an initialized enclave|
EMODT(SGX2) | 0FH | Address of a SECINFO | Address of the destination EPC page| | This leaf function modifies the type of an EPC page|
EPA(SGX1) | 0AH | Address of PT_VA | Effective address of the EPC page |   | This leaf function creates an empty version array in the EPC page |
EREMOVE(SGX1) | 03H |   | Effective address of the EPC page |  | This leaf function causes an EPC page to be un-associated with its SECS and be marked as unused | 
ETRACK(SGX1) | 0CH |  | Pointer to the SECS of the EPC page|  | This leaf function provides the mechanism for hardware to track that software has completed the required TLB address clears successfully | 
EWB(SGX1) | 0BH | Address of an PAGEINFO | Address of the EPC page | Address of a VA slot | This leaf function invalidates an EPC page and writes it out to main memory |

ENCLU Instruction | RAX | RBX | RCX | RDX | Description |
--- | --- | --- | --- | --- | --- |
EACCEPT(SGX2) | 05H | Address of a SECINFO | Address of the destination EPC page |  | This leaf function accepts changes to a page in the running enclave by verifying SECINFO and EPCM | 
EACCEPTCOPY(SGX2) | 07H | Address of a SECINFO | Address of the destination EPC page | Address of the source EPC page | This leaf function copies the contents of an existing EPC page into an uninitialized EPC page(created by EAUG) |
EENTER(SGX1) | 02H | Address of a TCS | Address of an AEP |  | The ENCLU[EENTER] instruction transfers execution to an enclave |
EEXIT(SGX1) | 04H | Target address outside the enclave |  |  | The ENCLU[EEXIT] instruction exits the currently executing enclave and branches to the location specified in RBX |
EGETKEY(SGX1) | 01H | Address to a KEYREQUEST | Address of the OUTPUTDATA |  | The ENCLU[EGETKEY] returns a 128-bit secret key from the processor specific key hierachy | 
EMODPE(SGX2) | 06H | Address of a SECINFO | Address of the destination EPC page |  | This leaf function extends the access rights associated with an existing EPC page in the running enclave |
EREPORT(SGX1) | 00H | Address of TARGETINFO | Address of REPORTDATA | Address where the REPORT is written to | This leaf function creates a cryptographic REPORT that describes the contents of an enclave |
ERESUME(SGX1) | 03H | Address of a TCS | Address of AEP | | The ENCLU[ERESUME] instruction resumes execution of an enclave