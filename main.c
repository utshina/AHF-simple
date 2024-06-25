/******************************************************************************

  The MIT License (MIT)

  Copyright (c) 2020 Takahiro Shinagawa (The University of Tokyo)

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

******************************************************************************/

/** ***************************************************************************
 * @file main.c
 * @brief A simple example of using Apple Hypervisor.framework (AHF)
 * @copyright Copyright (c) 2020 Takahiro Shinagawa (The University of Tokyo)
 * @license The MIT License (http://opensource.org/licenses/MIT)
 *************************************************************************** */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>

#define OR ==HV_SUCCESS?(void)0:
#define panic(x) (void)(fputs("panic: " x "\n",stderr),exit(1))

#define KiB *1L*1024
#define MiB *1L*1024*1024
#define GiB *1L*1024*1024*1024

const uint64_t PTE_P  = 1ULL <<  0; // Present
const uint64_t PTE_RW = 1ULL <<  1; // Read/Write
const uint64_t PTE_US = 1ULL <<  2; // User/Supervisor
const uint64_t PTE_PS = 1ULL <<  7; // Page Size
const uint64_t PTE_G  = 1ULL <<  8; // Global

const uint64_t CR0_PE = 1ULL <<  0; // Protection Enable
const uint64_t CR0_NE = 1ULL <<  5; // Paging Enable
const uint64_t CR0_PG = 1ULL << 31; // Paging Enable
const uint64_t CR4_PSE =  1ULL <<  4; // Page Size Extensions
const uint64_t CR4_PAE =  1ULL <<  5; // Physical Address Extension
const uint64_t CR4_VMXE = 1ULL <<  5; // 
const uint64_t EFER_LME = 1ULL <<  8; // IA-32e Mode Enable
const uint64_t EFER_LMA = 1ULL << 10; // IA-32e Mode Active

const uint64_t user_start = 4 KiB;
const uint64_t kernel_start = 1 GiB;
struct kernel {
	uint64_t pml4[512];
	uint64_t pdpt[512];
} *kernel;

const uint8_t user_code[][3] = {
	{ 0x0f, 0x01, 0xd9 }, // vmmcall for AMD
	{ 0x0f, 0x01, 0xc1 }, // vmcall for Intel
	{ 0xeb, 0xfe, 0x90 }, // loop
};


int
main(int argc, char *argv[])
{
	// create a VM
	hv_vm_create(HV_VM_DEFAULT)
		OR panic("hv_vm_create");

	// prepare and map kernel data structures
	assert((sizeof(*kernel) & (4 KiB - 1)) == 0); // 4 KiB align
	kernel = valloc(sizeof(*kernel));
	if (!kernel)
		panic("allocate kernel memory");
	memset(kernel, 0, sizeof(*kernel));
	kernel->pml4[0] = (kernel_start + offsetof(struct kernel, pdpt))
		| (PTE_P | PTE_RW | PTE_US);
	kernel->pdpt[0] = 0x0
		| (PTE_P | PTE_RW | PTE_US | PTE_PS);
	hv_vm_map(kernel, kernel_start, sizeof(*kernel), HV_MEMORY_READ | HV_MEMORY_WRITE)
		OR panic("map the kernel region");

	// map user space
	void *user_page;
	user_page = valloc(4 KiB);
	if (!user_page)
		panic("allocate user memory");
	memset(user_page, 0, 4 KiB);
	const int vendor = 2; // Intel only
	memcpy(user_page, user_code[vendor], sizeof(user_code[vendor]));
	hv_vm_map(user_page, user_start, 4 KiB, HV_MEMORY_READ | HV_MEMORY_EXEC)
		OR panic("map the user region");

	// create a vCPU
	hv_vcpuid_t vcpu;
	hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT)
		OR panic("create virtual processor");

	// setup VMCS
	uint64_t vmx_cap_pinbased, vmx_cap_procbased, vmx_cap_procbased2, vmx_cap_entry, vmx_cap_exit;
	hv_vmx_read_capability(HV_VMX_CAP_PINBASED, &vmx_cap_pinbased);
	hv_vmx_read_capability(HV_VMX_CAP_PROCBASED, &vmx_cap_procbased);
	hv_vmx_read_capability(HV_VMX_CAP_PROCBASED2, &vmx_cap_procbased2);
	hv_vmx_read_capability(HV_VMX_CAP_ENTRY, &vmx_cap_entry);
	hv_vmx_read_capability(HV_VMX_CAP_EXIT, &vmx_cap_exit);
#define cap2ctrl(cap,ctrl) (((ctrl) | ((cap) & 0xffffffff)) & ((cap) >> 32))
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_PIN_BASED, cap2ctrl(vmx_cap_pinbased, 0));
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CPU_BASED, cap2ctrl(vmx_cap_procbased, CPU_BASED_HLT | CPU_BASED_CR8_LOAD | CPU_BASED_CR8_STORE));
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CPU_BASED2, cap2ctrl(vmx_cap_procbased2, 0));
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS, cap2ctrl(vmx_cap_entry,
							   VMENTRY_LOAD_EFER | VMENTRY_GUEST_IA32E));
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_VMEXIT_CONTROLS, cap2ctrl(vmx_cap_exit, VMEXIT_LOAD_EFER | VMEXIT_SAVE_EFER));
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CR0_MASK, 0);
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CR0_SHADOW, 0);
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CR4_MASK, 0);
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0);

	// setup vCPU registers
	// hv_vcpu_write_register(vcpu, HV_X86_CR0, (CR0_PE | CR0_PG)) | 
	// hv_vcpu_write_register(vcpu, HV_X86_CR3, kernel_start + offsetof(struct kernel, pml4)) |
	// hv_vcpu_write_register(vcpu, HV_X86_CR4, (CR4_PSE | CR4_PAE | CR4_VMXE)) |
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR0, (CR0_PE | CR0_PG | CR0_NE | 1ULL << 1 | q
1ULL << 2)) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR3, kernel_start + offsetof(struct kernel, pml4)) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR4, (CR4_PSE | CR4_PAE | 1ULL << 9 | 1ULL << 18 | 1ULL << 10)) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_IA32_EFER, (EFER_LME | EFER_LMA)) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_BASE, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_AR, 0x209b) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_BASE, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_AR, 0x0093) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_BASE, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_AR, 0x0093) | 



	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES_BASE, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES_AR, 0x0093) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS_BASE, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS_AR, 0x0093) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS_BASE, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS_AR, 0x0093) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GDTR_BASE, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_LDTR_BASE, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_LDTR_LIMIT, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x18082) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_TR_BASE, 0) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_TR_LIMIT, 0xffff) | 
	hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_TR_AR, 0x808b) | 
	hv_vcpu_write_register(vcpu, HV_X86_CS, 0x08) | 
	hv_vcpu_write_register(vcpu, HV_X86_DS, 0x10) | 
	hv_vcpu_write_register(vcpu, HV_X86_ES, 0x10) | 
	hv_vcpu_write_register(vcpu, HV_X86_FS, 0x10) | 
	hv_vcpu_write_register(vcpu, HV_X86_FS, 0x10) | 
	hv_vcpu_write_register(vcpu, HV_X86_GS, 0x10) | 
	hv_vcpu_write_register(vcpu, HV_X86_SS, 0x10) | 
	hv_vcpu_write_register(vcpu, HV_X86_TR, 0) | 
	hv_vcpu_write_register(vcpu, HV_X86_LDTR, 0x0) | 
	hv_vcpu_write_register(vcpu, HV_X86_RIP, user_start) |
	hv_vcpu_write_register(vcpu, HV_X86_RSP, 0) |
	hv_vcpu_write_register(vcpu, HV_X86_RFLAGS, 0x02) |
	hv_vcpu_write_register(vcpu, HV_X86_XCR0, 0x01) 
		OR panic("set virtual processor registers");

	// run the VM
	uint64_t exit_reason;
	// hv_vcpu_run(vcpu);
	printf("%x\n", hv_vcpu_run_until(vcpu, HV_DEADLINE_FOREVER));
	//		OR panic("run virtual processor");
	hv_vmx_vcpu_read_vmcs(vcpu, VMCS_RO_EXIT_REASON, &exit_reason);
	printf("Exit reason: %llx\n", exit_reason);
	if (exit_reason == VMX_REASON_VMCALL)
		puts("The vmcall instruction is executed");

#if 0
	WHV_PARTITION_HANDLE handle;
	UINT16 vcpu = 0;
	int vendor;

	// Is Windows Hypervisor Platform (WHP) enabled?
	UINT32 size;
	WHV_CAPABILITY capability;
	WHvGetCapability(
		WHvCapabilityCodeHypervisorPresent,
		&capability, sizeof(capability), &size);
	if (!capability.HypervisorPresent)
		panic("Windows Hypervisor Platform is not enabled");

	// Check the processor vendor
	WHvGetCapability(
		WHvCapabilityCodeProcessorVendor,
		&capability, sizeof(capability), &size);
	vendor = capability.ProcessorVendor;
	if (vendor > 1)
		panic("Unsupported vendor");

	// create a VM
	WHvCreatePartition(&handle)
		OR panic("create partition");

	// set the VM properties
	UINT32 cpu_count = 1;
	WHvSetPartitionProperty(
		handle,
		WHvPartitionPropertyCodeProcessorCount,
		&cpu_count, sizeof(cpu_count))
		OR panic("set partition property (cpu count)");

	WHV_EXTENDED_VM_EXITS vmexits = { 0 };
	vmexits.HypercallExit = 1;
	WHvSetPartitionProperty(
		handle,
		WHvPartitionPropertyCodeExtendedVmExits,
		&vmexits, sizeof(vmexits))
		OR panic("set partition property (vmexits)");

	WHvSetupPartition(handle)
		OR panic("setup partition");

	// prepare and map kernel data structures
	assert((sizeof(*kernel) & (4 KiB - 1)) == 0); // 4 KiB align
	kernel = (struct kernel *)aligned_alloc(4 KiB, sizeof(*kernel));
	if (!kernel)
		panic("aligned_alloc");
	memset(kernel, 0, sizeof(*kernel));
	kernel->pml4[0] = (kernel_start + offsetof(struct kernel, pdpt))
		| (PTE_P | PTE_RW | PTE_US);
	kernel->pdpt[0] = 0x0
		| (PTE_P | PTE_RW | PTE_US | PTE_PS);
	WHvMapGpaRange(handle, kernel, kernel_start, sizeof(*kernel),
		       WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite)
		OR panic("map the kernel region");

	// map user space
	void *user_page = aligned_alloc(4 KiB, 4 KiB);
	if (!user_page)
		panic("aligned_alloc");
	memcpy(user_page, user_code[vendor], sizeof(user_code[vendor]));
	WHvMapGpaRange(handle, user_page, user_start, 4 KiB,
		       WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagExecute)
		OR panic("map the user region");

	// create a vCPU
	WHvCreateVirtualProcessor(handle, vcpu, 0)
		OR panic("create virtual processor");

	// setup vCPU registers
	enum {
		Cr0, Cr3, Cr4, Efer,
		Cs, Ss, Ds, Es, Rip,
		RegNum
	};
	WHV_REGISTER_NAME regname[RegNum];
	regname[Cr0] =  WHvX64RegisterCr0;
	regname[Cr3] =  WHvX64RegisterCr3;
	regname[Cr4] =  WHvX64RegisterCr4;
	regname[Efer] = WHvX64RegisterEfer;
	regname[Cs] =   WHvX64RegisterCs;
	regname[Ss] =   WHvX64RegisterSs;
	regname[Ds] =   WHvX64RegisterDs;
	regname[Es] =   WHvX64RegisterEs;
	regname[Rip] =  WHvX64RegisterRip;
	WHV_REGISTER_VALUE regvalue[RegNum];
	regvalue[Cr0].Reg64 = (CR0_PE | CR0_PG);
	regvalue[Cr3].Reg64 = kernel_start + offsetof(struct kernel, pml4);
	regvalue[Cr4].Reg64 = (CR4_PSE | CR4_PAE);
	regvalue[Efer].Reg64 = (EFER_LME | EFER_LMA);
	WHV_X64_SEGMENT_REGISTER CodeSegment;
	CodeSegment.Base = 0;
	CodeSegment.Limit = 0xffff;
	CodeSegment.Selector = 0x08;
	CodeSegment.Attributes = 0xa0fb;
	regvalue[Cs].Segment = CodeSegment;
	WHV_X64_SEGMENT_REGISTER DataSegment;
	DataSegment.Base = 0;
	DataSegment.Limit = 0xffff;
	DataSegment.Selector = 0x10;
	DataSegment.Attributes = 0xc0f3;
	regvalue[Ss].Segment = DataSegment;
	regvalue[Ds].Segment = DataSegment;
	regvalue[Es].Segment = DataSegment;
	regvalue[Rip].Reg64 = user_start;
	WHvSetVirtualProcessorRegisters(
		handle, vcpu, regname, RegNum, regvalue)
		OR panic("set virtual processor registers");

	// run the VM
	WHV_RUN_VP_EXIT_CONTEXT context;


	printf("Exit reason: %x\n", context.ExitReason);
	if (context.ExitReason == WHvRunVpExitReasonHypercall)
		puts("The vmcall instruction is executed");
#endif
	return 0;
}
