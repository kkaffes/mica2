sMICA
-----

Install DPDK v19.11 using https://doc.dpdk.org/guides-19.11/linux_gsg/build_dpdk.html#installation-of-dpdk-target-environment-using-make.

Setup the environment:

1. cd mica2/build
2. ln -s src/mica/test/*.json .
3. Allocate huge pages: sudo sh -c 'for i in /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages; do echo 16384 > $i; done'
4. Set up MICA: ../script/setup.sh
5. Server-side: sudo python3 dpdk-devbind.py --force -b igb_uio 0000:04:00.0
5. Client-side: sudo python3 usertools/dpdk-devbind.py --force -b igb_uio 0000:06:00.0
6. Start etcd: ./etcd --advertise-client-urls http://10.79.7.17:2379 --listen-client-urls http://10.79.7.17:2379 --enable-v2

Run the server:
1. sudo ./server

Run the client:
2. sudo ./netbench 0
