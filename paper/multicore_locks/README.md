# Multicore: The Case is not Closed Yet (USENIX ATC'16)

## Machines

We evaluated locks on three different machines:

| Name                           | **AMD-64**              | **AMD-48**              | Intel-48                           |
| ------------------------------ | ----------------------- | ----------------------- | ---------------------------------- |
| Total #cores                   | 64                      | 48                      | 48 (no hyperthreading)             |
| ------------------------------ | ----------------------- | ----------------------- | ---------------------------------- |
| **Server model**               | Dell PowerEdge R815     | Dell PowerEdge R815     | SuperMicro SuperServer 4048B-TR4FT |
| ------------------------------ | ----------------------- | ----------------------- | ---------------------------------- |
| **Processors**                 | 4x AMD Opteron 6272     | 4x AMD Opteron 6344     | 4x Intel Xeon E7-4830 v3           |
|                                | Bulldozer / Interlagos  | Piledriver / Abu Dhabi  | Haswell-EX                         |
| Core clock                     | 2.1 GHz                 | 2.6 GHz                 | 2.1 GHz                            |
| Last-level cache (per node)    | 8 MB                    | 8 MB                    | 30 MB                              |
| ------------------------------ | ----------------------- | ----------------------- | ---------------------------------- |
| **Interconnect**               | HT3 - 6.4 GT/s per link | HT3 - 6.4 GT/s per link | QPI - 8 GT/s per link              |
| ------------------------------ | ----------------------- | ----------------------- | ---------------------------------- |
| **Memory**                     | 256 GB DDR3 1600 MHz    | 64 GB DDR3 1600 MHz     | 256 GB DDR4 2133 MHz               |
| #NUMA nodes (#cores/node)      | 8 (8)                   | 8 (6)                   | 4 (12)                             |
| ------------------------------ | ----------------------- | ----------------------- | ---------------------------------- |
| **Network interfaces** (10 GbE)| 2x 2-port Intel 82599   | 2x 2-port Intel 82599   | 2-port Intel X540-AT2              |
| ------------------------------ | ----------------------- | ----------------------- | ---------------------------------- |
| **OS / tools**                | Ubuntu 12.04            | Ubuntu 12.04            | Ubuntu 12.04                       |
| Linux kernel                   | 3.17.6 (CFS scheduler)  | 3.17.6 (CFS scheduler)  | 3.17.6 (CFS scheduler)             |
| Glibc                          | 2.15                    | 2.15                    | 2.15                               |
| Gcc                            | 4.6.3                   | 4.6.3                   | 4.6.4                              |

## Results

The [`datasets/`](datasets/) directory contains all the experimental results data for the three machines discussed in the [companion technical report](tech-rep.pdf).
Note that the number of cores per node (and thus, the number of threads per node) is not the same on every machine (see the above table).

The throughput column corresponds to:

- Raw throughput for long-lived applications (applications ending by `_ll`), ssl_proxy and MySQL
- Execution time (in seconds) transformed in throughput (`1/exec`)

## Workloads

For each benchmark that we considered, the table below indicates the workloads we used.
Notes :

- Parameters were selected to avoid very short/long running times.
- For the benchmarks using files, we first copied the files into a `tmpfs` to avoid disk I/O latencies.
- For long-lived applications, we first let a 30s warmup for the application (starting when the throughput was more than 0), then we took the average throughput over 60s.

| Benchmark			 | Workload                                                      | Note |
| ---------			 | --------                                                      | ---- |
| barnes			 | PARSEC 3.0 native                                             | |
| blackscholes		 | PARSEC 3.0 native                                             | |
| bodytrack			 | PARSEC 3.0 native                                             | |
| canneal			 | PARSEC 3.0 native                                             | |
| dedup				 | PARSEC 3.0 native                                             | |
| facesim			 | PARSEC 3.0 native                                             | |
| ferret			 | PARSEC 3.0 native                                             | |
| fft				 | -m 26                                                         | This is between simlarge (m = 24) and native(m = 28) |
| fluidanimate		 | PARSEC 3.0 native                                             | |
| fmm				 | PARSEC 3.0 native                                             | |
| freqmine			 | PARSEC 3.0 native                                             | |
| histogram			 | BMP img of 2GB                                                | A patch is needed to support image of this size |
| kmeans			 | -p 5000000, other default                                     | |
| linear_regression	 | 3GB key file                                                  | The key file is a concatenation of the key_file_500MB.txt |
| lu_cb				 | PARSEC 3.0 native                                             | |
| lu_ncb			 | PARSEC 3.0 native                                             | |
| matrix_multiply	 | side of matrix = 3000, size of Row block = 1                  | |
| mysqld			 | Cloudstone dataset                                            | MySQL version 5.7.7 compiled with MUTEXTYPE=OS. A patch is needed to capture throughput |
| ocean_cp			 | PARSEC 3.0 native with n=2050                                 | |
| ocean_ncp			 | PARSEC 3.0 native with n=2050                                 | |
| pca				 | numcols = 4000, numrows = 4000                                | |
| pca_ll			 | numcols = 9000, numrows = 9000                                | A patch is needed to capture throughput |
| p_raytrace		 | PARSEC 3.0 native                                             | |
| radiosity			 | PARSEC 3.0 simlarge                                           | |
| radiosity_ll		 | PARSEC 3.0 simlarge with -bf = 1.5e-5                         | A patch is needed to capture throughput and support the workload |
| radix				 | PARSEC 3.0 native                                             | |
| s_raytrace		 | PARSEC 3.0 native                                             | |
| s_raytrace_ll		 | PARSEC 3.0 native with -a = 8192                              | A patch is needed to capture throughput |
| ssl_proxy			 | One injector per thread sending 100 bytes msg. in closed-loop | The ssl_proxy is built on top of boost::asio and uses SSL to encrypt connections |
| streamcluster		 | PARSEC 3.0 simlarge with ITER = 3                             | You need to recompile streamcluster and modify the file streamcluster.cpp to change the #define ITER value |
| streamcluster		 | PARSEC 3.0 simlarge with ITER = 300                           | You need to recompile streamcluster and modify the file streamcluster.cpp to change the #define ITER value. You also need a patch to capture throughput |
| string_match		 | 20GB key file                                                 | The key file is a concatenation of the key_file_500MB.txt. A patch is needed to support this file size |
| swaptions			 | PARSEC 3.0 native                                             | |
| vips				 | PARSEC 3.0 native                                             | |
| volrend			 | PARSEC 3.0 native                                             | |
| water_nsquared	 | PARSEC 3.0 native                                             | |
| water_spatial		 | PARSEC 3.0 native                                             | |
| word_count		 | 1GB word file                                                 | The key file is a concatenation of the word_100MB.txt |
| x264				 | PARSEC 3.0 native                                             | * *|

## Patches

A set of patches are available for the workloads.

- *Parsec*: [expose calls to shared library for interposition](patches/parsec.patch)
- *Phoenix*: [allow deactivating per-core pinning](patches/phoenix.patch)
- *histogram*: [allow big file](patches/histogram.patch)
- *string_match*: [allow big file](patches/string_match.patch)
- *pca*: [throughput for long-lived version](patches/pca.patch)
- *streamcluster*: [throughput for long-lived version](patches/streamcluster.patch)
- *s_raytrace*: [throughput for long-lived version](patches/s_raytrace.patch)
- *radiosity*: [throughput for long-lived version](patches/radiosity.patch)
- *mysql*: [throughput for long-lived version](patches/mysql.patch)
