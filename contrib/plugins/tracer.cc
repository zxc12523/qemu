/*
 * Copyright (C) 2020, Pranith Kumar <bobby.prani@gmail.com>
 *
 */
extern "C" {
#include "qemu-plugin.h"
}

#include <iostream>
#include <sstream>
#include <fstream>
#include <set>
#include <map>
#include <mutex>
#include <vector>
#include <algorithm>

#include <glib.h>
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <zlib.h>

#define INTERVAL_SIZE 100000000 /* 100M instructions */

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static enum qemu_plugin_mem_rw rw = QEMU_PLUGIN_MEM_RW;
static qemu_plugin_id_t plugin_id;

/* Plugins need to take care of their own locking */
static std::mutex lock;

static uint64_t inst_count = 0; /* executed instruction count */
static uint64_t inst_dumped = 0; /* traced instruction count  */

#ifdef SIMPT
static std::ifstream simpts_file;
static std::vector<std::ofstream> trace_files;
static std::set<uint64_t> interval_set;
static std::set<uint64_t> interval_cur;
#endif

static bool tracing_enabled = false;
static uint32_t max_interval = 0;
static uint32_t interval = 0;

static std::map<uint64_t, struct qemu_plugin_insn *> instructions;
static std::map<uint32_t, uint32_t> interval2idx;

void plugin_exit(qemu_plugin_id_t id, void *p)
{
#ifdef SIMPT
    simpts_file.close();

    for(int i=0;i<trace_files.size();i++) {
        trace_files[i].close();
    }
#endif
}

static void plugin_init(std::string& bench_name, std::string& arch)
{
#ifdef SIMPT
    std::string simpts_file_name = bench_name + ".simpts";
    simpts_file.open(simpts_file_name.c_str(), std::ifstream::in);

    int i = 0;

    while (!simpts_file.eof())
    {
        std::string line, interval, seq_no;
        std::getline(simpts_file, line);

        char *s = (char*)line.c_str();

        // std::cerr << line << std::endl;

        // not good enough, FIXME
        if (!line.empty()) {
            uint32_t val = atoi(strtok(s, " "));
            char* group = strtok(NULL, " ");

            std::cerr << "interval: " << val <<  " group: " << group << " idx: " << i << '\n';

            interval_set.insert(val);
            interval2idx[val] = i;
            max_interval = std::max(max_interval, val);

            std::string trace_file_name = bench_name + std::to_string(i++) + ".txt";
            std::ofstream trace_file(trace_file_name.c_str(), std::ofstream::out);
            trace_files.push_back(std::move(trace_file));
        }
    }
#endif
}

static void vcpu_insn_exec_before(unsigned int cpu_index, void *udata)
{
    lock.lock();

    struct qemu_plugin_insn *insn = (struct qemu_plugin_insn *)udata;

    // char* disas = qemu_plugin_insn_disas(insn);
    // const void* data = qemu_plugin_insn_data(insn);

    interval = inst_dumped / INTERVAL_SIZE;

#ifdef SIMPT
    if (interval_cur.find(interval) == interval_cur.end()) {
        std::cerr << "Current Interval: " << interval << '\n';
        std::cerr.flush();
        interval_cur.insert(interval);
    }

    if (interval_set.find(interval) != interval_set.end()) {
        trace_files[interval2idx[interval]] << (char *)udata << '\n';
    }
#else
    std::cerr << "0x" << (char *)udata << '\n';
#endif


    // std::cerr << " Instruction: " << (const char*) qemu_plugin_insn_disas(insn) << std::endl;

    inst_dumped++;

    // if (inst_dumped >= INTERVAL_SIZE) {
    //     std::cerr << "Inst Dumped: " << inst_dumped << '\n';
    //     std::cerr.flush();
    //     // qemu_plugin_reset(plugin_id, callback_reset);
    // }

    lock.unlock();
}

static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t meminfo, uint64_t vaddr, void *udata) {
    uint64_t pc = (uint64_t)udata;
    std::cerr << "Mem callback 0x" << std::hex << pc << " vaddr:" << vaddr
              << " store:" << qemu_plugin_mem_is_store(meminfo) << std::endl;
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);

static void callback_reset(qemu_plugin_id_t id)
{
    std::cerr << "Resetting plugin" << std::endl;
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
}

static void tb_exec(unsigned int cpu_index, void *udata)
{
    lock.lock();
    
    // interval = inst_count / INTERVAL_SIZE;

    struct qemu_plugin_tb *tb = (struct qemu_plugin_tb *)udata;

    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t insns = qemu_plugin_tb_n_insns(tb);

    inst_count += insns;

    std::cerr << "Inst Counts: " << std::dec << inst_count << ", PC: " << std::hex << pc << ", Insns: " << std::dec << insns << '\n';

    // if (interval_cur.find(interval) == interval_cur.end()) {
    //     std::cerr << "Current Interval: " << interval << '\n';
    //     std::cerr.flush();
    //     interval_cur.insert(interval);
    // }

    // // std::cerr << "Inst Count: " << inst_count << " Inst Dumped: " << inst_dumped << " Inst Pairs: " << instructions.size() << '\n';

    // if (interval_set.find(interval) != interval_set.end()) {

    //     size_t insns = qemu_plugin_tb_n_insns(tb);

    //     for (size_t i = 0; i < insns; i++) {
    //         struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
    //         trace_files[interval2idx[interval]] << qemu_plugin_insn_size(insn);
    //         trace_files[interval2idx[interval]].write((char*)qemu_plugin_insn_data(insn), qemu_plugin_insn_size(insn));
    //         inst_dumped++;
    //     }
    // }

    // if (inst_dumped > INTERVAL_SIZE) {
    //     std::cerr << "Inst Dumped: " << inst_dumped << '\n';
    //     std::cerr.flush();
    //     inst_dumped = 0;
    //     // qemu_plugin_reset(plugin_id, callback_reset);
    // }

    lock.unlock();
}

static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t insns = qemu_plugin_tb_n_insns(tb);
    // qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64, &inst_count, insns);
    // qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_NO_REGS, tb);

    for (size_t i = 0; i < insns; i++) {

        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        uint32_t insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));

        char *output = g_strdup_printf("%"PRIx32"", insn_opcode);

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec_before, QEMU_PLUGIN_CB_NO_REGS, (void *) output);
        // qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem, QEMU_PLUGIN_CB_NO_REGS, rw, (void *)pc);
        
        // std::cerr << "Installing inst and mem cbs for insn " << qemu_plugin_insn_disas(insn) << " insn: " << std::hex << *(int*)qemu_plugin_insn_data(insn) << std::endl;
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    std::string bench_name("trace");
    std::string arch("riscv64");

    plugin_id = id;
    plugin_init(bench_name, arch);

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
