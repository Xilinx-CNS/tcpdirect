/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2021 Advanced Micro Devices, Inc. */
#ifndef ZF_REACTOR_LOOP_H
#define ZF_REACTOR_LOOP_H

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/private/zf_emu.h>
#include <zf_internal/rx_res.h>
#include <zf_internal/tcp_tx.h>
#include <zf_internal/tcp.h>

#include <zf_internal/private/tcp_fast.h>
#include <zf_internal/private/zf_stack_def.h>

#include <etherfabric/vi.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/internal/internal.h>

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <cstdlib>
#include <thread>
#include <iostream>
#include <iterator>
#include <utility>
#include <chrono>
#include <vector>
#include <numeric>
#include <cmath>
#include <map>
#include <algorithm>
#include <atomic>
#include <unordered_set>

#include "../tap/tap.h"

#include "abstract_zocket_pair.h"

#ifdef NDEBUG
#define DEBUG(x)
#define WARM_UP_ITERS 1000
#else
#define DEBUG(x) x
#define WARM_UP_ITERS 0
#endif

#define N_PROCESSORS sysconf(_SC_NPROCESSORS_ONLN)
#define LOG_SECTION(x) std::cout << "\n****************************************\n" \
                                 << x                                              \
                                 << "\n****************************************\n\n"
struct App;
struct Result;
namespace utils
{
    using time_point_t = std::chrono::high_resolution_clock::time_point;
    using res_t = std::map<std::string, double>;
    using BenchmarkFunction = Result (*)(App *); // function pointer
    using WorkerFunction = void (*)(App *, std::vector<time_point_t>&); // function pointer
}

struct Result
{
    std::string name;
    double duration;
    utils::res_t results;
};

struct App
{
    using f_map = std::map<std::string, utils::BenchmarkFunction>;

    /* ZF related */
    zf_attr *attr[2];
    zf_stack *stacks[2]; // index 0 coresponds to the RX stack
    zf_muxer_set *muxer;
    zft *tcp_tx;
    zft *tcp_rx;
    abstract_zocket_pair zockets;

    /* CPU/Node */
    int cpu_map[2] = {2, 4};

    /* General */
    int itercount = 1000000;
    utils::res_t multipliers = {{"ns", 1e9}, {"us", 1e6}, {"ms", 1e3}, {"s", 1}};
    f_map funcs;

    /* Options */
    bool comp = false;
    std::string unit = "ns";
    std::unordered_set<std::string> tests;

    /* Methods */
    App();
    void start();
    void display_args();
    void display_test_results(Result &test);
    Result invoke(const std::string &fstr);
};

#endif /* ZF_REACTOR_LOOP_H */
