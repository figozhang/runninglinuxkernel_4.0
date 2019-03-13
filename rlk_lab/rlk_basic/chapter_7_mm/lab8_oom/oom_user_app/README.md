## 说明

该实验为《奔跑吧Linux入门版》中第七章的实验8的参考代码。

> 程序说明：本程序创建了一个子进程，在子进程中根据cpu个数，创建了相应个数的线程，在每个线程中不停的申请内存，直到出错为止。父进程等待子进程的结束。
最后会触发内核的`oom机制`, 通过`dmesg`命令可以看到`oom`机制打印的信息。

1. 编译运行 `on ARM32`
$ export CC=arm-linux-gnueabi-gcc
$ make
$ cp oom /home/rlk/rlk_basic/runninglinuxkernel__4.0/kmodules/  #copy into
kmodues folder

#run Qemu 
$ cd /home/rlk/rlk_basic/runninglinuxkernel_4.0/
$ sh run.sh arm32
$ ./oom

#here is the log on ARM32.

/mnt # ./oom
expected victim is 782.
thread(b6f0c300), allocating 10485760 bytes.
thread(b670b300), allocating 10485760 bytes.
thread(b5f0a300), allocating 10485760 bytes.

...

oom invoked oom-killer: gfp_mask=0x200da, order=0, oom_score_adj=0
oom cpuset=/ mems_allowed=0
CPU: 1 PID: 783 Comm: oom Not tainted 4.0.0+ #4
Hardware name: ARM-Versatile Express
[<c002475c>] (unwind_backtrace) from [<c001d640>] (show_stack+0x2c/0x38)
[<c001d640>] (show_stack) from [<c05956c4>] (__dump_stack+0x1c/0x24)
[<c05956c4>] (__dump_stack) from [<c059579c>] (dump_stack+0xd0/0xf8)
[<c059579c>] (dump_stack) from [<c01a81b4>] (dump_header+0x104/0x158)
[<c01a81b4>] (dump_header) from [<c01a87a4>] (oom_kill_process+0x208/0xa48)
[<c01a87a4>] (oom_kill_process) from [<c01a99a8>] (__out_of_memory+0x410/0x43c)
[<c01a99a8>] (__out_of_memory) from [<c01a9a38>] (out_of_memory+0x64/0x88)
[<c01a9a38>] (out_of_memory) from [<c01b08b4>] (__alloc_pages_nodemask+0xed8/0x1208)
[<c01b08b4>] (__alloc_pages_nodemask) from [<c02003e4>] (do_anonymous_page+0x2c8/0x6cc)
[<c02003e4>] (do_anonymous_page) from [<c02022c8>] (handle_pte_fault+0xcc/0x364)
[<c02022c8>] (handle_pte_fault) from [<c0202864>] (__handle_mm_fault+0x304/0x314)
[<c0202864>] (__handle_mm_fault) from [<c0202964>] (handle_mm_fault+0xf0/0x14c)
[<c0202964>] (handle_mm_fault) from [<c0b0d4c4>] (__do_page_fault+0x10c/0x168)
[<c0b0d4c4>] (__do_page_fault) from [<c0b0d704>] (do_page_fault+0x1e4/0x6b0)
[<c0b0d704>] (do_page_fault) from [<c000879c>] (do_DataAbort+0x64/0x104)
[<c000879c>] (do_DataAbort) from [<c0b0cc5c>] (__dabt_usr+0x3c/0x40)
Exception stack(0xc527bfb0 to 0xc527bff8)
bfa0:                                     b1c00000 00a00000 00000007 b21c1000
bfc0: b6f0c300 ffffffff b6f0c518 00000152 bea70cc2 0009a4c0 bea70cc4 b6f0bcec
bfe0: 00000000 b6f0bcc8 0001035c 00010398 80000010 ffffffff
Mem-info:
Normal per-cpu:
CPU    0: hi:   18, btch:   3 usd:   0
CPU    1: hi:   18, btch:   3 usd:   0
CPU    2: hi:   18, btch:   3 usd:   0
CPU    3: hi:   18, btch:   3 usd:   2
active_anon:16781 inactive_anon:1052 isolated_anon:0
 active_file:3 inactive_file:3 isolated_file:0
 unevictable:0 dirty:0 writeback:0 unstable:0
 free:283 slab_reclaimable:1012 slab_unreclaimable:1693
 mapped:305 shmem:1596 pagetables:39 bounce:0
 free_cma:0
Normal free:1132kB min:1156kB low:1444kB high:1732kB active_anon:67124kB inactive_anon:4208kB active_file:12kB inactive_file:12kB unevictable:0kB isolated(anon):0kB isolated(file):0kB present:102400kB managed:87400kB mlocked:0kB dirty:0kB writeback:0kB mapped:1220kB shmem:6384kB slab_reclaimable:4016kB slab_unreclaimable:6772kB kernel_stack:360kB pagetables:156kB unstable:0kB bounce:0kB free_cma:0kB writeback_tmp:0kB pages_scanned:28 all_unreclaimable? no
lowmem_reserve[]: 0 0 0
Normal: 2*4kB (MR) 6*8kB (EMR) 1*16kB (R) 0*32kB 1*64kB (R) 0*128kB 0*256kB 0*512kB 1*1024kB (R) 0*2048kB 0*4096kB = 1160kB
1606 total pagecache pages
0 pages in swap cache
Swap cache stats: add 0, delete 0, find 0/0
Free swap  = 0kB
Total swap = 0kB
25600 pages of RAM
354 free pages
3750 reserved pages
1692 slab pages
569 pages shared
0 pages swap cached
[ pid ]   uid  tgid total_vm      rss nr_ptes nr_pmds swapents oom_score_adj name
[  769]     0   769      577      309       3       0        0             0 sh
[  781]     0   781      191        1       2       0        0             0 oom
[  782]     0   782    26563    16153      40       0        0             0 oom
Out of memory: Kill process 782 (oom) score 716 or sacrifice child
Killed process 782 (oom) total-vm:106252kB, anon-rss:64612kB, file-rss:0kB
victim signalled: 9
/mnt #



2. 编译运行 `on x86_64`

$ export CC=gcc
$ make
gcc -o oom oom.c -lpthread --static
$ ./oom 
expected victim is 6435.
thread(7fed7c5bd700), allocating 1073741824 bytes.
thread(7fed7adba700), allocating 1073741824 bytes.
thread(7fed7bdbc700), allocating 1073741824 bytes.
thread(7fed7b5bb700), allocating 1073741824 bytes.
thread(7fed7bdbc700), allocating 1073741824 bytes.
thread(7fed7b5bb700), allocating 1073741824 bytes.
thread(7fed7c5bd700), allocating 1073741824 bytes.
thread(7fed7adba700), allocating 1073741824 bytes.
victim signalled: 9
```

## 内核日志信息

```
[81399.968234] oom invoked oom-killer: gfp_mask=0x6280ca(GFP_HIGHUSER_MOVABLE|__GFP_ZERO), nodemask=(null), order=0, oom_score_adj=0
[81399.968236] oom cpuset=/ mems_allowed=0
[81399.968241] CPU: 0 PID: 6436 Comm: oom Not tainted 4.20.12 #1
[81399.968242] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
[81399.968243] Call Trace:
[81399.968252]  dump_stack+0x63/0x85
[81399.968255]  dump_header+0x71/0x295
[81399.968258]  oom_kill_process+0x254/0x280
[81399.968259]  out_of_memory+0x2b1/0x4f0
[81399.968262]  __alloc_pages_slowpath+0xabd/0xdf0
[81399.968265]  ? call_function_interrupt+0xa/0x20
[81399.968268]  __alloc_pages_nodemask+0x28f/0x2b0
[81399.968271]  alloc_pages_vma+0x88/0x1f0
[81399.968274]  __handle_mm_fault+0x8ee/0x1310
[81399.968276]  handle_mm_fault+0xe3/0x220
[81399.968279]  __do_page_fault+0x295/0x510
[81399.968281]  ? page_fault+0x8/0x30
[81399.968282]  do_page_fault+0x2d/0xf0
[81399.968284]  ? error_entry+0x100/0x100
[81399.968285]  ? page_fault+0x8/0x30
[81399.968287]  page_fault+0x1e/0x30
[81399.968289] RIP: 0033:0x560728d6cb34
[81399.968293] Code: Bad RIP value.
[81399.968294] RSP: 002b:00007fed7c5bce90 EFLAGS: 00010206
[81399.968296] RAX: 00007febe54fe000 RBX: 0000000000000000 RCX: 00007fed7c6d9a13
[81399.968297] RDX: 00000000314fe000 RSI: 0000000040000000 RDI: 0000000000000000
[81399.968297] RBP: 00007fed7c5bcec0 R08: 00000000ffffffff R09: 0000000000000000
[81399.968298] R10: 0000000000000022 R11: 0000000000000246 R12: 00007fed7c5bcfc0
[81399.968299] R13: 0000000000000000 R14: 0000000000000000 R15: 00007fff9fedd730
[81399.968300] Mem-Info:
[81399.968304] active_anon:1245960 inactive_anon:177996 isolated_anon:32
                active_file:71 inactive_file:0 isolated_file:0
                unevictable:0 dirty:0 writeback:17 unstable:0
                slab_reclaimable:5956 slab_unreclaimable:5367
                mapped:1 shmem:0 pagetables:6361 bounce:0
                free:23001 free_pcp:0 free_cma:0
[81399.968307] Node 0 active_anon:4983840kB inactive_anon:711984kB active_file:284kB inactive_file:0kB unevictable:0kB isolated(anon):128kB isolated(file):0kB mapped:4kB dirty:0kB writeback:68kB shmem:0kB shmem_thp: 0kB shmem_pmdmapped: 0kB anon_thp: 0kB writeback_tmp:0kB unstable:0kB all_unreclaimable? yes
[81399.968308] Node 0 DMA free:15900kB min:200kB low:248kB high:296kB active_anon:0kB inactive_anon:0kB active_file:0kB inactive_file:0kB unevictable:0kB writepending:0kB present:15992kB managed:15908kB mlocked:0kB kernel_stack:0kB pagetables:0kB bounce:0kB free_pcp:0kB local_pcp:0kB free_cma:0kB
[81399.968311] lowmem_reserve[]: 0 2922 5161 5161 5161
[81399.968313] Node 0 DMA32 free:47016kB min:38144kB low:47680kB high:57216kB active_anon:2819340kB inactive_anon:712232kB active_file:56kB inactive_file:160kB unevictable:0kB writepending:68kB present:3653568kB managed:3588032kB mlocked:0kB kernel_stack:16kB pagetables:8660kB bounce:0kB free_pcp:0kB local_pcp:0kB free_cma:0kB
[81399.968316] lowmem_reserve[]: 0 0 2239 2239 2239
[81399.968318] Node 0 Normal free:29088kB min:29232kB low:36540kB high:43848kB active_anon:2164608kB inactive_anon:8kB active_file:672kB inactive_file:0kB unevictable:0kB writepending:0kB present:2423808kB managed:2301784kB mlocked:0kB kernel_stack:3152kB pagetables:16784kB bounce:0kB free_pcp:0kB local_pcp:0kB free_cma:0kB
[81399.968321] lowmem_reserve[]: 0 0 0 0 0
[81399.968323] Node 0 DMA: 1*4kB (U) 1*8kB (U) 1*16kB (U) 0*32kB 2*64kB (U) 1*128kB (U) 1*256kB (U) 0*512kB 1*1024kB (U) 1*2048kB (M) 3*4096kB (M) = 15900kB
[81399.968330] Node 0 DMA32: 25*4kB (UM) 6*8kB (UM) 48*16kB (UME) 29*32kB (UME) 37*64kB (ME) 19*128kB (ME) 15*256kB (E) 16*512kB (UME) 2*1024kB (ME) 1*2048kB (E) 6*4096kB (M) = 47348kB
[81399.968337] Node 0 Normal: 292*4kB (UME) 134*8kB (UME) 174*16kB (UME) 122*32kB (UME) 69*64kB (UME) 35*128kB (UE) 18*256kB (UME) 7*512kB (UME) 3*1024kB (UME) 0*2048kB 0*4096kB = 29088kB
[81399.968345] Node 0 hugepages_total=0 hugepages_free=0 hugepages_surp=0 hugepages_size=2048kB
[81399.968345] 10755 total pagecache pages
[81399.968347] 10655 pages in swap cache
[81399.968348] Swap cache stats: add 1026547, delete 1015860, find 1677/2904
[81399.968348] Free swap  = 0kB
[81399.968349] Total swap = 2097148kB
[81399.968349] 1523342 pages RAM
[81399.968350] 0 pages HighMem/MovableOnly
[81399.968350] 46911 pages reserved
[81399.968351] 0 pages cma reserved
[81399.968351] 0 pages hwpoisoned
[81399.968352] Tasks state (memory values in pages):
[81399.968352] [  pid  ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name
[81399.968356] [    310]     0   310    27496       19   233472      183             0 systemd-journal
[81399.968358] [    329]     0   329    11690        0   114688      495         -1000 systemd-udevd
[81399.968359] [    369] 62583   369    35994        0   184320      155             0 systemd-timesyn
[81399.968361] [    374]   101   374    17687        0   176128      173             0 systemd-resolve
[81399.968363] [    570]     0   570     1138        0    53248       41             0 acpid
[81399.968365] [    571]     0   571   106814        0   331776      365             0 ModemManager
[81399.968366] [    576]   102   576    65759        4   163840      256             0 rsyslogd
[81399.968368] [    604]     0   604     8268        0   114688       82             0 cron
[81399.968369] [    606]     0   606   125668        0   344064      440             0 udisksd
[81399.968372] [    609]     0   609    43067        0   221184     1983             0 networkd-dispat
[81399.968373] [    612]     0   612    27602       26   122880       56             0 irqbalance
[81399.968375] [    617]     0   617    17646        0   180224      190             0 systemd-logind
[81399.968377] [    618]     0   618    72323        0   217088      238             0 accounts-daemon
[81399.968378] [    623]   103   623    12682        1   139264      333          -900 dbus-daemon
[81399.968380] [    703]     0   703   139021        2   438272      711             0 NetworkManager
[81399.968382] [    704]     0   704    11188        2   135168      131             0 wpa_supplicant
[81399.968383] [    706]   117   706    11814        0   139264      104             0 avahi-daemon
[81399.968385] [    725]   117   725    11769        0   135168       85             0 avahi-daemon
[81399.968386] [    732]     0   732    73234        1   217088      651             0 polkitd
[81399.968388] [    780]     0   780    47242        0   262144     2000             0 unattended-upgr
[81399.968389] [    794]     0   794    18074        0   176128      186         -1000 sshd
[81399.968391] [    801]     0   801    91056        1   217088      252             0 lightdm
[81399.968392] [    809]     0   809   156147        1   548864     4286             0 Xorg
[81399.968394] [    814]     0   814     4483        0    77824       38             0 agetty
[81399.968396] [    843]   113   843    97118        1   389120      427             0 whoopsie
[81399.968397] [    869]   114   869    14234        7   147456      107             0 kerneloops
[81399.968399] [    872]   114   872    14234       12   135168      101             0 kerneloops
[81399.968400] [    964]     0   964    61603        1   249856      236             0 lightdm
[81399.968402] [    967]   110   967    19187        1   192512      310             0 systemd
[81399.968404] [    968]   110   968    28491        0   245760      629             0 (sd-pam)
[81399.968406] [   1364]     0  1364    92079        0   315392      436             0 packagekitd
[81399.968407] [   1413]     0  1413    27520        1   253952      255             0 sshd
[81399.968409] [   1415]  1000  1415    19188        0   184320      290             0 systemd
[81399.968411] [   1416]  1000  1416    28491        0   245760      629             0 (sd-pam)
[81399.968412] [   1444]   110  1444     1157        0    53248       23             0 lightdm-greeter
[81399.968414] [   1446]   110  1446   374497        0   888832     3107             0 kylin-greeter
[81399.968416] [   1470]   110  1470    12479        1   143360      140             0 dbus-daemon
[81399.968417] [   1474]   110  1474    87327        0   180224      181             0 at-spi-bus-laun
[81399.968419] [   1479]   110  1479    12449        0   135168      102             0 dbus-daemon
[81399.968420] [   1483]   110  1483    55160        0   192512      184             0 at-spi2-registr
[81399.968422] [   1491]   110  1491    71653        1   192512      222             0 gvfsd
[81399.968423] [   1502]   110  1502    87644        0   176128      218             0 gvfsd-fuse
[81399.968425] [   1520]   110  1520    46976        1   135168      157             0 dconf-service
[81399.968426] [   1530]     0  1530    25738        1   237568      174             0 lightdm
[81399.968428] [   1532]   110  1532   278653        0   520192     1427             0 ukui-settings-d
[81399.968429] [   1590]  1000  1590    27520       27   245760      234             0 sshd
[81399.968431] [   1591]  1000  1591     6567      202    90112      238             0 bash
[81399.968433] [   1600]   110  1600   155964        1   356352      773             0 pulseaudio
[81399.968434] [   1601]   109  1601    45876        0   122880       89             0 rtkit-daemon
[81399.968436] [   2660]     0  2660     6415        1    98304      307             0 dhclient
[81399.968437] [   2916]     0  2916    25582        1   249856      310             0 cupsd
[81399.968439] [   2917]     0  2917    75880        0   344064      394             0 cups-browsed
[81399.968441] [   6434]  1000  6434     1674        0    57344       26             0 oom
[81399.968443] [   6435]  1000  6435  2123406  1412546 15409152   498959             0 oom
[81399.968444] Out of memory: Kill process 6435 (oom) score 957 or sacrifice child
[81399.968458] Killed process 6435 (oom) total-vm:8493624kB, anon-rss:5650184kB, file-rss:0kB, shmem-rss:0kB
[81400.193300] oom_reaper: reaped process 6435 (oom), now anon-rss:0kB, file-rss:0kB, shmem-rss:0kB
```
