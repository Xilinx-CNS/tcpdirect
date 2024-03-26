/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2021 Advanced Micro Devices, Inc. */

/**
 * Documented as "Reactor Benchmarking Tool"
 *
 * Most of the code is in C++ (requires at least C++14), with certain parts
 * written in C (pthreads, using the zf library, some printfs etc).
 *
 * ### SUPPORTED TESTS
 * - Reactor loop test
 * - Reactor loop null test
 */

#include "zfreactorloop.h"

static bool verbose = false;

#ifdef NDEBUG
#define TRACE(x...)
#else
#define TRACE(x...) ({ \
  if( verbose ) \
    printf(x); \
})

#endif

namespace utils
{
  using duration_t = std::chrono::nanoseconds;

  static void set_thread_affinity(int cpu_index)
  {
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(cpu_index, &cpus);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpus);
  }

  static double get_variance(const std::vector<double> &v, const double &mean)
  {
    double accum = 0.0;
    for (auto &d : v)
      accum += (d - mean) * (d - mean);
    return accum / v.size();
  }

  static double fast_nth_percentile(std::vector<double> &v, int n)
  {
    // O(N) time complexity on average (nth element quickselect), O(1) space, modifies v in-place
    size_t idx = (v.size() * n + 99) / 100 - 1;
    std::nth_element(v.begin(), v.begin() + idx, v.end()); // partially sorts vector in place

    // Whole number, take average of two middle
    if (v.size() * n % 100 == 0)
    {
      double next_item = *std::min_element(v.begin() + idx + 1, v.end());
      return 0.5 * (v[idx] + next_item);
    }
    else
      return v[idx];
  }

  static utils::res_t get_results(std::vector<double> &v)
  {
    double sum = std::accumulate(v.cbegin(), v.cend(), 0.0);
    double mean = sum / v.size();
    double var = get_variance(v, mean);
    double stdev = sqrt(var);
    double min = *std::min_element(v.begin(), v.end());
    double max = *std::max_element(v.begin(), v.end());
    double _50th_percentile = fast_nth_percentile(v, 50);
    double _90th_percentile = fast_nth_percentile(v, 90);
    double _99th_percentile = fast_nth_percentile(v, 99);
    return {
        {"mean", mean},
        {"median", _50th_percentile},
        {"90%ile", _90th_percentile},
        {"99%ile", _99th_percentile},
        {"min", min},
        {"max", max},
        {"var", var},
        {"stdev", stdev}};
  }

  /**
   * @brief Obtain the difference between 2 test results
   *
   * @param a
   * @param b
   * @return Result
   * where test[key] = a[key] - b[key]
   */
  static Result difference(Result &a, Result &b)
  {
    Result combined;
    for (const auto &e : a.results)
      combined.results[e.first] = e.second - b.results[e.first];
    combined.name = "Difference of " + a.name + " & " + b.name;
    combined.duration = a.duration - b.duration;
    return combined;
  }

  static void usage_msg(FILE *f)
  {
    fprintf(f, "usage:\n");
    fprintf(f, "  zf reactor benchmarking tool <options>\n");
    fprintf(f, "\n");
    fprintf(f, "options:\n");
    fprintf(f, "  -h       Print this usage message\n");
    fprintf(f, "  -r       Specify the CPU on which the reader (stack 0) is bound\n");
    fprintf(f, "  -w       Specify the CPU on which the writer (stack 1) is bound\n");
    fprintf(f, "  -i       Number of iterations\n");
    fprintf(f, "  -t       Test to benchmark, specify multiple for multiple test runs\n");
    fprintf(f, "  -c       Enable comparisons for tests with null test\n");
    fprintf(f, "  -u       Specify units for reporting (ns, us, ms, s)\n");
    fprintf(f, "  -v       Enable verbose logging\n");
  }

  /**
   * ### BENCHMARK FUNCTIONS
   *
   * Benchmark functions are generic benchmarking setups that reside in the utils
   * namespace.
   *
   * i.e.
   * using BenchmarkFunction = Result (*)(App *);
   *
   * At the very least, each benchmark function should do the following tasks:
   * 1. Prepare data structures to store timing results
   * 2. Launch worker threads to populate timing results
   * 3. Wait for workers to finish
   * 4. Populate Result data structure with measurements and return to caller,
   *    which is typically the driver function of a test
   *
   * In general:
   * - Preallocate vectors to be passed into the worker functions
   * - Define generic benchmark functions in the utils namespace then call them
   *   from test namespaces.
   *
   */

  /**
   * @brief Runs a symmetric benchmark.
   *  Uses 2 threads: 1 writer and 1 reader, each thread mirrors the other
   * around the benchmark subject and produces a time measurement
   *
   * @param app
   * @param test_name
   * @return Result
   */
  static Result run_symmetric_benchmark(App *app,
                                        std::string test_name,
                                        WorkerFunction write_worker,
                                        WorkerFunction read_worker)
  {
    LOG_SECTION(test_name + ": start");
    std::cout << test_name << ": thread id=" << syscall(__NR_gettid) << '\n';
    std::cout << "Number of processors: " << N_PROCESSORS << '\n';
    std::cout << "Total iterations: " << app->itercount + WARM_UP_ITERS << '\n';

    std::vector<utils::time_point_t> write_times(app->itercount);
    std::vector<utils::time_point_t> read_times(app->itercount);

    auto start = std::chrono::high_resolution_clock::now();
    std::thread w_thread(write_worker, app, std::ref(write_times));
    std::thread r_thread(read_worker, app, std::ref(read_times));

    w_thread.join();
    r_thread.join();

    Result test;
    std::vector<double> latencies(app->itercount);
    for (int i = 0; i < app->itercount; ++i)
    {
      auto ns_int = std::chrono::duration_cast<utils::duration_t>(read_times[i] - write_times[i]);
      latencies[i] = std::chrono::duration<double>(ns_int).count();
    }

    test.results = get_results(latencies);
    auto end = std::chrono::high_resolution_clock::now();
    auto test_duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
    test.duration = test_duration.count();
    test.name = test_name;
    return test;
  }
}

/**
 * ### TESTS
 *
 * Each test is encapsulated by a namespace, which contains a driver function
 * (typically named 'run') and worker functions. The driver function calls
 * the benchmarking function of choice, passing in the worker functions as
 * arguments.
 *
 * e.g.
 * namespace my_test {
 *    // Worker functions and other related functions here
 *
 *    // Driver
 *    static Result run(App *app)
 *    {
 *        auto test = my_benchmark_func(app, "my_test", worker_1, worker_2);
 *        app->display_test_results(test);
 *        return test;
 *    }
 * }
 *
 * ### WORKER FUNCTIONS
 *
 * Worker functions are subroutines executed by threads launched by benchmarking
 * functions, residing in a test's namespace.
 *
 * i.e.
 * using WorkerFunction = void (*)(App *, std::vector<time_point_t>&);
 *
 * Each worker should:
 * - Pass in a size-preallocated vector of time_point_t objects by reference and use
 *   indices to store times.
 * - Set its own thread affinity at the start of its routine.
 * - Ignore the first WARM_UP_ITERS iterations.
 */

/**
 * @brief Reactor loop test
 * # Description
 * - Measures the latency between a packet (pftf) being written to the RX queue
 *   and detection of an OVERLAPPED event.
 *
 * # Motivation
 * - Useful to help inform whether the reactor loop design for X3 needs to be changed,
 *   as the RX queue will be potentially shared by multiple agents.
 * - Another matter is emergence of more complex CPU architecture (chiplets, CCXs etc),
 *   of which the implications are not too clear.
 * - Allow benchmarking of the latency on various HW (AMD/Intel  various generations) with
 *   data in local L3 or remote L3 or different chiplet etc.
 * - Enable performance assessment and allow experimenting with different loop designs for
 *   different HW etc.
 * - Useful for assessing regressions - make sure we don't regress X2 when implmenting X3
 */
namespace reactor_loop_test
{
#define EIGHT_BYTE_PAYLOAD 0xFFFFFFFFFFFFFFFFul
#define ONE_BYTE_PAYLOAD (uint8_t)0xFFu
#define PAYLOAD ONE_BYTE_PAYLOAD

  static auto payload = PAYLOAD;
  static std::atomic<bool> ready(false);

  struct msg
  {
    zft_msg header;
    iovec iov[SW_RECVQ_MAX];
  };

  /* ZF data structure functions */
  static int init(zf_stack **stack_out, zf_attr **attr_out, const char *interface)
  {
    // Ignore proper handling of errors for now
    int rc = zf_init();
    if (rc != 0)
      return rc;
    rc = zf_attr_alloc(attr_out);
    if (rc != 0)
      return rc;
    /* Request the default allocation of buffers explicitly. */
    rc = zf_attr_set_int(*attr_out, "n_bufs", 0);
    if (rc != 0)
      return rc;
    rc = zf_attr_set_str(*attr_out, "interface", interface);
    if (rc != 0)
      return rc;
    rc = zf_stack_alloc(*attr_out, stack_out);
    if (rc != 0)
      return rc;
    return 0;
  }

  static int fini(zf_stack *stack, zf_attr *attr)
  {
    int rc = zf_stack_free(stack);
    if (rc != 0)
      return rc;
    zf_attr_free(attr);
    rc = zf_deinit();
    if (rc != 0)
      return rc;
    return 0;
  }

  static void allocate_zocket_pair(App *app)
  {
    alloc_tcp_pair_t(app->stacks[1], app->stacks[0], app->attr[0], &app->zockets, [] {});
    app->tcp_tx = (zft *)app->zockets.opaque_tx; // Use this to send packets
    app->tcp_rx = (zft *)app->zockets.opaque_rx;
    ZF_TRY(zf_muxer_alloc(app->stacks[0], &app->muxer));

    const epoll_event in_event_ovl = {
        .events = ZF_EPOLLIN_OVERLAPPED | EPOLLIN,
        .data = {.u32 = ZF_EPOLLIN_OVERLAPPED},
    };

    ZF_TRY(zf_muxer_add(app->muxer, zft_to_waitable(app->tcp_rx), &in_event_ovl));
  }

  static void deallocate_zocket_pair(App *app)
  {
    ZF_TRY(zf_muxer_del(zft_to_waitable(app->tcp_rx)));
    zf_muxer_free(app->muxer);
    zft_opaque_close(&app->zockets);
  }

  /* Writer */
  static char *get_write_destination(zf_stack *stack)
  {
    int nic = stack->next_poll_nic;
    ef_vi *vi = &stack->nic[nic].vi;
    pkt_id next_packet_id = ef_vi_next_rx_rq_id(vi);
    return PKT_BUF_RX_START_BY_ID(&stack->pool, next_packet_id);
  }

  static void prepare_tx_zocket(zf_tcp *tcp)
  {
    TRACE("writer: populate header in TX\n");
    tcp_pcb *pcb = &tcp->pcb;
    tcphdr *tcp_hdr = zf_tx_tcphdr(&tcp->tst);
    iphdr *ip_hdr = zf_tx_iphdr(&tcp->tst);

    auto src = &tcp->tst.pkt;

    TRACE("writer: pcb->snd_lbb=%u, "
          "pcb->snd_next=%u,"
          "pcb->snd_delegated = %u, "
          "pcb->rcv_nxt = %u, "
          "ntohl(tcp_hdr->seq) = %u\n",
          pcb->snd_lbb,
          pcb->snd_nxt, pcb->snd_delegated,
          pcb->rcv_nxt, ntohl(tcp_hdr->seq));

    tcp_output_populate_header_fast(tcp_hdr, pcb->snd_nxt,
                                    pcb->rcv_nxt, pcb->rcv_ann_wnd, 0);

    // Payload
    uint16_t payload_offset = IP_HLEN + TCP_HLEN + ETH_HLEN;
    TRACE("writer: packet offset = %u\n", payload_offset);

    ((decltype(payload) *)src)[payload_offset] = payload; // Write data to the data segment on TX

    ip_hdr->tot_len = htons(payload_offset - ETH_HLEN + sizeof(decltype(payload)));
  }

  static utils::time_point_t write_to_destination(void *src, void *dest)
  {
    TRACE("writer: clock start, writing to RX\n");
    utils::time_point_t time = std::chrono::high_resolution_clock::now();
    __builtin_memcpy((uint64_t *)dest + 1, (const uint64_t *)src + 1, 64 - 8);
    ci_wmb();
    *(volatile uint64_t *)dest = *(const uint64_t *)src;
    return time;
  }

  static void write_worker(App *app, std::vector<utils::time_point_t> &res)
  {
    TRACE("writer: id=%ld, successfully started\n", syscall(__NR_gettid));
    utils::set_thread_affinity(app->cpu_map[0]);
    auto stack = app->stacks[0];

    for (int i = 0; i < WARM_UP_ITERS + app->itercount; ++i)
    {
      TRACE("writer: enter loop\n");
      TRACE("writer: waiting for ready signal from RX\n");
      while (!ready)
        ;
      auto tcp = (zf_tcp *)app->tcp_tx;
      prepare_tx_zocket(tcp);
      auto src = &tcp->tst.pkt;
      auto dest = get_write_destination(stack);

      auto time = write_to_destination(src, dest);

      ready = false;
      if (i >= WARM_UP_ITERS)
      {
        res[i - WARM_UP_ITERS] = time;
        TRACE("writer: finished %d/%d iteration(s)\n", i + 1, app->itercount);
      }
    }
  }

  /* Reader */
  static void drain_stacks(App *app)
  {
    for (auto &stack : app->stacks)
      while (zf_reactor_perform(stack) != 0)
        ;
  }

  static void read_worker(App *app, std::vector<utils::time_point_t> &res)
  {
    TRACE("reader: id=%ld, successfully started\n", syscall(__NR_gettid));
    utils::set_thread_affinity(app->cpu_map[1]);
    epoll_event event;
    utils::time_point_t time;

    for (int i = 0; i < WARM_UP_ITERS + app->itercount; ++i)
    {
      msg msg;
      TRACE("reader: Signalling ready to read\n");
      ready = true;
      // Spin for events
      while (1)
      {
        msg.iov[0].iov_len = sizeof(decltype(payload));
        msg.header.iovcnt = SW_RECVQ_MAX;
        TRACE("reader: Spinning...\n");
        while (zf_muxer_wait(app->muxer, &event, 1, 0) == 0)
          ;
        if (event.events & ZF_EPOLLIN_OVERLAPPED)
        {
          time = std::chrono::high_resolution_clock::now();
          TRACE("reader: ZF_EPOLLIN_OVERLAPPED received - do zft_zc_recv\n");
          zft_zc_recv(app->tcp_rx, &msg.header, ZF_OVERLAPPED_WAIT);
          if (msg.header.iovcnt == 0)
            continue;
          TRACE("reader: ZF_OVERLAPPED_WAIT ok\n");
          TRACE("reader: Flushing\n");
          zft_send_single(app->tcp_tx, "a", 1, 0);
          zft_zc_recv(app->tcp_rx, &msg.header, ZF_OVERLAPPED_COMPLETE);
          TRACE("reader: ZF_OVERLAPPED_COMPLETE\n");
          if (msg.header.iovcnt == 0)
          {
            TRACE("reader: zft_zc_recv msg.header.iovcnt == 0, retrying\n");
            continue;
          }
          TRACE("reader: zft_zc_recv_done\n");
          zft_zc_recv_done(app->tcp_rx, &msg.header);
          break;
        }
        else
        {
          zft_zc_recv(app->tcp_rx, &msg.header, 0);
          zft_zc_recv_done(app->tcp_rx, &msg.header);
        }
        TRACE("reader: No event/invalid event detected, try spinning again\n");
      }

      if (i >= WARM_UP_ITERS)
      {
        res[i - WARM_UP_ITERS] = time;
        TRACE("reader: finished %d/%d iteration(s)\n", i + 1, app->itercount);
      }

      drain_stacks(app);
    }
  }

  static Result run(App *app)
  {
    ZF_TRY(init(&app->stacks[0], &app->attr[0], ZF_EMU_B2B0));
    ZF_TRY(init(&app->stacks[1], &app->attr[1], ZF_EMU_B2B1));
    allocate_zocket_pair(app);
    auto test = utils::run_symmetric_benchmark(app, "reactor_loop_test",
                                               write_worker, read_worker);
    app->display_test_results(test);
    deallocate_zocket_pair(app);
    ZF_TRY(fini(app->stacks[1], app->attr[1]));
    ZF_TRY(fini(app->stacks[0], app->attr[0]));
    LOG_SECTION("reactor_loop_test: done");
    return test;
  }
}

/**
 * @brief Reactor loop null test
 *
 * - The reference test to compare with the reactor loop test. Mimics the timing
 *   sequence of reactor_loop_test, without the packet send and reactor loop overhead.
 */
namespace reactor_loop_null_test
{
  static std::atomic<bool> state(false);

  static void write_worker(App *app, std::vector<utils::time_point_t> &res)
  {
    TRACE("writer: id=%ld, successfully started\n", syscall(__NR_gettid));
    utils::set_thread_affinity(app->cpu_map[0]);

    for (int i = 0; i < WARM_UP_ITERS + app->itercount; ++i)
    {
      auto time = std::chrono::high_resolution_clock::now();
      state = true;
      while (state.load(std::memory_order_relaxed))
        ;

      if (i >= WARM_UP_ITERS)
      {
        res[i - WARM_UP_ITERS] = time;
        TRACE("writer: finished %d/%d iteration(s)\n", i + 1, app->itercount);
      }
    }
  }

  static void read_worker(App *app, std::vector<utils::time_point_t> &res)
  {
    TRACE("reader: id=%ld, successfully started\n", syscall(__NR_gettid));
    utils::set_thread_affinity(app->cpu_map[1]);

    for (int i = 0; i < WARM_UP_ITERS + app->itercount; ++i)
    {
      while (!state)
        ;
      auto time = std::chrono::high_resolution_clock::now();
      state.store(false, std::memory_order_relaxed);
      if (i >= WARM_UP_ITERS)
      {
        res[i - WARM_UP_ITERS] = time;
        TRACE("reader: finished %d/%d iteration(s)\n", i + 1, app->itercount);
      }
    }
  }

  static Result run(App *app)
  {
    auto test = utils::run_symmetric_benchmark(app, "reactor_loop_null_test", write_worker, read_worker);
    app->display_test_results(test);
    return test;
  }
}

/* Class methods */
App::App()
{
  this->funcs["reactor_loop_null"] = &reactor_loop_null_test::run;
  this->funcs["reactor_loop"] = &reactor_loop_test::run;
}

/**
 * @brief Invoke a function from its string keyword
 *
 * @param fstr
 * @return Result
 */
Result App::invoke(const std::string &fstr)
{
  auto it = this->funcs.find(fstr);
  if (it == this->funcs.end())
  {
    std::cout << "No functions specified, going with reactor_loop";
    return this->funcs["reactor_loop"](this);
  }
  return (*it->second)(this);
}

void App::start()
{
  LOG_SECTION("Start app");
  this->display_args();

#ifdef NDEBUG
  ZF_TEST(this->itercount > WARM_UP_ITERS);
#endif

  Result ref;
  // If comparing and not specified explicitly,
  // run null test and remove from queue if exists
  if (this->comp)
  {
    auto it = this->tests.find("null");
    if (it != this->tests.end())
      this->tests.erase(it);
    ref = reactor_loop_null_test::run(this);
  }

  if (this->tests.size() == 0)
  {
    std::cout << "No tests specified, defaulting to reactor loop test\n";
    this->tests.insert("loop");
  }
  std::vector<Result> test_results;
  for (const auto &test_name : this->tests)
    test_results.push_back(this->invoke(test_name));
  if (this->comp)
    for (auto &test : test_results)
    {
      auto diff = utils::difference(test, ref);
      this->display_test_results(diff);
    }
}

void App::display_args()
{
  std::cout << "Iterations: " << this->itercount << '\n';
  std::cout << "CPU affinities:\n";
  unsigned sz = std::size(this->cpu_map);
  for (unsigned i = 0; i < sz; ++i)
    std::cout << "- Stack " << i << ": " << this->cpu_map[i] << '\n';
}

void App::display_test_results(Result &test)
{
  LOG_SECTION("test results");
  std::cout << "[Metadata]\n";
  std::cout << "Test name:\t" << test.name << '\n';
  std::cout << "w_thread cpu:\t" << this->cpu_map[1] << '\n';
  std::cout << "r_thread cpu:\t" << this->cpu_map[0] << '\n';
  std::cout << "Total iters:\t" << this->itercount + WARM_UP_ITERS << '\n';
  std::cout << "Ignored iters:\t" << WARM_UP_ITERS << '\n';
  std::cout << "Duration:\t" << test.duration << "s (" << this->itercount << " trials)\n";
  std::cout << "\n[Data]\n";
  for (const auto &e : test.results)
    std::cout << e.first << "\t=>\t" << e.second * this->multipliers[this->unit]
              << " " << this->unit << '\n';
}

int main(int argc, char *argv[])
{
  App the_app, *app = &the_app;

  /**
   * Pass optional args using flags:
   * ... make run_zfreactorloop ... TEST_OPTS='<flags>'
   * e.g. '-w 6 -r 4 -i 100000'
   */
  int c;
  while ((c = getopt(argc, argv, "hw:r:i:t:cu:")) != -1)
    switch (c)
    {
    case 'h':
      utils::usage_msg(stdout);
      exit(0);
    case 'r':
      app->cpu_map[0] = atoi(optarg);
      break;
    case 'w':
      app->cpu_map[1] = atoi(optarg);
      break;
    case 'i':
      app->itercount = atoi(optarg);
      break;
    case 't':
      app->tests.insert(optarg);
      break;
    case 'c':
      app->comp = true;
      break;
    case 'u':
      if (app->multipliers.find(optarg) == app->multipliers.end())
      {
        std::cout << "Invalid unit, defaulting to nanoseconds\n";
        app->unit = "ns";
      }
      else
        app->unit = optarg;
      break;
    case 'v':
      verbose = true;
      break;
    case '?':
      exit(1);
    default:
      ZF_TEST(0);
    }

  if (argc == 0)
    std::cout << "No additional args, using defaults\n";
  argc -= optind;
  argv += optind;

  app->start();
  LOG_SECTION("Exiting app");
  plan(1);
  ok(1, "all fine");
  done_testing();
}
