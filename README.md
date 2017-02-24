# LiTL: Library for Transparent Lock interposition

LiTL is a library that allows executing a program based on Pthread mutex locks with another locking algorithm.

- Author : Hugo Guiroux <hugo.guiroux at gmail dot com>
- Related Publication: *Multicore Locks: the Case is Not Closed Yet*, Hugo Guiroux, Renaud Lachaize, Vivien Quéma, USENIX ATC'16.

## Building

`make`

### Dependencies

- numactl
- coreutils
- make
- gcc
- git

## Execution

Launch your application using one of the provided scripts.
The name of the script to you use depends on the chosen lock.

Examples:

 * If you want to use the MCS lock with the spin-then-park policy, do the following: `./libmcs_spin_then_park.sh my_program`

 * For the CLH lock with the spin policy, do the following: `./libclh_spinlock.sh my_program`

 * For the ticket lock (which has its waiting policy hardcoded - see below), do the following: `./libticket_original.sh my_program`

## Details

### Usage
The algorithms are named according to the following schema: `lib{algo}_{waiting_policy}.sh`.

The waiting policy can either be spinlock, spin_then_park or original.

Some algorithms come with different waiting policies (Malthusian, MCS, C-BO-MCS, CLH).
For example, if you want to execute your application with the MCS lock, using a spin-then-park waiting policy,
use `libmcs_spinlock.sh`.

For the other algorithms, the name of the script to use is of the form `lib{algo}_original.sh`.
In this case, the waiting policy depends on the one used in the original design of the corresponding lock (spin in most cases).

The library uses `LD_PRELOAD` to intercept calls to most of the `pthread_mutex_*` functions.

### Supported algorithms

| Name | Ref | Waiting Policy Supported | Name in the Paper [LOC] | Notes and acknowledgments |
| ---  | --- | --- | --- | --- |
| **ALOCK-EPFL** | [AND] | original (spin) | alock-ls | From libslock |
| **Backoff** | [MCS] | original (spin) | backoff | From concurrencykit |
| **C-BO-MCS**| [COH] | spinlock or spin-then-park | c-bo-mcs_spin and c-bo-mcs_stp|  |
| **CLH** | [SYN] | spinlock of spin-then-park | clh_spin and clh_stp | |
| **CLH-EPFL** | [SYN] | original (spin) | clh-ls | From libslock |
| **C-PTL-TKT** | [COH] | original (spin) | c-ptl-tkt | |
| **C-TKT-TKT** | [COH] | original (spin) | c-tkt-tkt | |
| **HMCS** | [HMC] | original (spin) | hmcs | |
| **HT-LOCK-EPFL** | [EVR] | original (spin) | hticket-ls | From libslock |
| **HYS-HMCS** | [HYS] | original (spin) | ahmcs | |
| **Malthusian** | [MAL] | spinlock or spin-then-park | malth_spin and malth_stp | This is the Malthusian-MCS version. |
| **Mutexee** | [MUT] | original (spin_then_park) | mutexee | From lockin |
| **MCS** | [MCS] | spinlock or spin-then-park | mcs_spin and mcs_stp | From RCL |
| **MCS-EPFL** | [MCS] | original (spin) | mcs-ls | From libslock |
| **MCS-TP** | [PRE] | original (spin hybrid) | mcs-timepub | From RCL |
| **Partitioned** | [PAR] | original (spin) | partitioned | |
| **Pthread-Adaptive** | [ADP] | original (spin_then_park) | pthreadadapt | Wrapper around pthread lock with adaptive policy |
| **Pthread-Interpose** | - | original (park) | pthread | Wrapper around classic pthread lock |
| **Spinlock** | [SYN] | original (spin) | spinlock | |
| **Spinlock-EPFL** | [SYN] | original (spin) | spinlock-ls | From libslock |
| **Ticket** | [MCS] | original (spin) | ticket | From lockless |
| **Ticket-EPFL** | [MCS] | original (spin) | ticket-ls | From libslock |
| **TTAS** | [AND] | original (spin) | ttas | |
| **TTAS-EPFL** | [AND] | original (spin) | ttas-ls | From libslock |

Note that the pthread-adaptive and pthread-interpose wrappers are provided only for fair comparison with the other algorithms (i.e., to introduce the same library interposition overhead).

### Support for condition variables

#### Summary of the approach

As explained in [LOC], we rely on classic Pthread condition variables to implement condition variables.
Here is some pseudo-code to summarize the approach:
```C
// return values and error checks
// omitted for simplification

pthread_mutex_lock(pthread_mutex_t *m) {
    optimized_mutex_t *om;
    om = get_optimized_mutex(m);
    if (om == null) {
        om = create_and_store_optim_mutex(m);
    }
    optimized_mutex_lock(om);
    real_pthread_mutex_lock(m);
}

pthread_mutex_unlock(pthread_mutex_t *m) {
    optimized_mutex_t *om;
    om = get_optimized_mutex(m);
    optimized_mutex_unlock(om);
    real_pthread_mutex_unlock(m);
}

pthread_cond_wait(pthread_cond_t *c,
                  pthread_mutex_t *m) {
    optimized_mutex_t *om;
    om = get_optimized_mutex(m);
    optimized_mutex_unlock(om);
    real_pthread_cond_wait(c, m);
    real_pthread_mutex_unlock(m);
    optimized_mutex_lock(om);
    real_pthread_mutex_lock(m);
}

// Note that the pthread_cond_signal and
// pthread_cond_broadcast primitives
// do not need to be interposed
```

This strategy does not introduce contention on the Pthread lock, as the latter is only requested by the holder of
the optimized lock associated with the critical section.

Some people have raised concerns about the possibility that several threads contended on the Pthread lock, especially for
workloads using `pthread_cond_broadcast`.
However, on Glibc/Linux, `pthread_cond_broadcast` is implemented (via the `futex` syscall) in a way such that it does not
wake up several threads at the same time. Indeed, according to the source code of the `pthread_cond_broadcast`
implementation, the broadcast function simply wakes up a single thread from the wait queue of the condition variable
and transfers the remaining threads to the wait queue of the Pthread lock. This is also confirmed in the `futex(2)` man page.
So, overall, for workloads that use `pthread_cond_broadcast` and/or `pthread_cond_signal`, it is unlikely to have more than
two threads contending for the Pthread lock at the same time.

#### Disabling support for condition variables

By default, the locks are built with the above-described support for condition variables.
However, if you know that the target application does not use condition variables, you can build the locks without it.
This allows optimizing the critical path for lock acquisition/release by removing the need to acquire/release the underlying Pthread lock.
To do so, use `make no_cond_var`.


### Trylock primitives

#### Implementation
Some algorithms do not come officially with a trylock primitive (i.e., non blocking lock request).
Here is how we implemented trylock for them :

- Cohorting: first trylock the local lock, and if needed trylock the top lock. If acquiring the top lock fails, unlock the local lock.
- HMCS: same idea as the one for the cohorting locks
- HYS-HMCS: as the algorithm supports fast-path, we only trylock the root MCS lock.
- Malthusian: just trylock like with a classical MCS lock.
- Ticket lock: the grant and request tickets are two 32-bit consecutive integers that are considered as a single 64-bit integer when trylocking.
- Partitioned Ticket: we cannot use the trick of the ticket lock because there are only 64-bit atomic ops and we have an array of tickets. So we first check if there is anybody waiting for the lock and if not, we try to lock (we may wait a little if threads come between the check and the acquisition).

#### Unsupported locks
To the best of our knowledge, the design of these algorithms does not support trylock semantics:

- CLH and CLH-EPFL
- HTLOCK-EPFL


### Adding a new lock

The library is designed to be extensible. In order to introduce a new lock algorithm, consider the following steps:

1. Edit Makefile.config: add one line with the format `algo_waitingstrategy` (`algo` without spaces in lowercase, `waitingstrategy` is `original`, `spinlock` or `spin_then_park`)
2. Add a file `include/algo.h`: take `spinlock` as an example
3. Add a file `src/algo.c`: take `spinlock` as an example
4. Modify the top of the `interpose.c` file to add a `#ifdef` for your algorithm (the Makefile takes care of everything)

Remarks:

- Several helper functions are available in `src/utils.c` and `src/utils.h`.
- If each thread needs its context for a lock, see `include/mcs.h` (`#define NEED_CONTEXT 1` is important)
- If you want to automatically support different waiting policies, use `#define SUPPORT_WAITING 1` and `waiting_policy_{sleep/wake}`. Look into `src/mcs.c` for an example.
- There is an example of a non-lock (`src/concurrency.c`) to show a case where the library can be used for logging statistics about locks (instead of replacing the original lock algorithm).

### Cascading interposition libraries

You may want to capture statistics for different locks. For example, if you want to capture the concurrency of the MCS algorithm, you can do the following:

`./libconcurrency_original.sh ./libmcs_spinlock.sh my_program`

#### Details
In order to be able to chain interposition libraries, we must add versions to the symbols we export.
This is done using a symbol map (see `src/interpose.map`) and by adding a `symver` asm symbol after the function declaration (see `src/interpose.c`).
Without that, the library is not able to get the function pointer address of the next function using `dlvsym`.

## References and acknowledgments

### Lock algorithms
- [ADP] Kaz Kylhyky. 2014. What is PTHREAD_MUTEX_ADAPTIVE_NP? http://stackoverflow.com/a/25168942
- [AND] Thomas E. Anderson. 1990. The Performance of Spin Lock Alternatives for Shared-Memory Multiprocessors. IEEE Trans. Parallel Distrib. Syst. 1, 1 (January 1990).
- [COH] Dave Dice, Virendra J. Marathe, and Nir Shavit. 2015. Lock Cohorting: A General Technique for Designing NUMA Locks. ACM Trans. Parallel Comput. 1, 2, Article 13 (February 2015).
- [EVR] Tudor David, Rachid Guerraoui, and Vasileios Trigonakis. 2013. Everything you always wanted to know about synchronization but were afraid to ask. In Proceedings of the Twenty-Fourth ACM Symposium on Operating Systems Principles (SOSP '13).
- [HMC] Milind Chabbi, Michael Fagan, and John Mellor-Crummey. 2015. High performance locks for multi-level NUMA systems. In Proceedings of the 20th ACM SIGPLAN Symposium on Principles and Practice of Parallel Programming (PPoPP 2015).
- [HYS] Milind Chabbi and John Mellor-Crummey. 2016. Contention-conscious, locality-preserving locks. In Proceedings of the 21st ACM SIGPLAN Symposium on Principles and Practice of Parallel Programming (PPoPP '16).
- [LOC] Hugo Guiroux, Renaud Lachaize, and Vivien Quéma. 2016. Multicore Locks: the Case is Not Closed Yet (USENIX ATC'16).
- [MAL] Dave Dice. 2015. Malthusian Locks. In CoRR (arXiv).
- [MUT] Babak Falsafi, Rachid Guerraoui, Javier Picorel, and Vasileios Trigonakis. 302+. Unlocking Energy (USENIX ATC'16).
- [MCS] John M. Mellor-Crummey and Michael L. Scott. 1991. Algorithms for scalable synchronization on shared-memory multiprocessors. ACM Trans. Comput. Syst. 9, 1 (February 1991).
- [PAR] David Dice. 2011. Brief announcement: a partitioned ticket lock. In Proceedings of the twenty-third annual ACM symposium on Parallelism in algorithms and architectures (SPAA '11)
- [PRE] Bijun He, William N. Scherer, and Michael L. Scott. 2005. Preemption adaptivity in time-published queue-based spin locks. In Proceedings of the 12th international conference on High Performance Computing (HiPC'05)
- [RCL] Jean-Pierre Lozi, Florian David, Gaël Thomas, Julia Lawall, and Gilles Muller. 2016. Fast and Portable Locking for Multicore Architectures. ACM Trans. Comput. Syst. 33, 4, Article 13 (January 2016)
- [SYN] Michael L. Scott. 2013. Shared-Memory Synchronization. Morgan & Claypool Publishers.

### Implementations
Some lock implementations are borrowed (fully or partially) from source code repositories developed by other people.
While we try to cite the authors of the original implementation (and the corresponding license) at the beginning of each file, we may have made mistakes and omissions. Please contact us if you notice any issue.

Sources:

- [RCL] http://rclrepository.gforge.inria.fr/
- [EVR] https://github.com/tudordavid/libslock
- http://locklessinc.com/articles/locks/
- https://github.com/concurrencykit/ck

LiTL also uses the [CLHT](https://github.com/LPD-EPFL/CLHT) hashtable.
This hashtable is used to link a pthread_mutex_lock with the underlying data structure of the interposed lock (e.g., MCS).
