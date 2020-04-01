RUST_BACKTRACE=1 ./build/cargo_target/debug/cloud-hypervisor --kernel ./vmlinux.bin --disk path=rootfs.img --cmdline "console=hvc0 reboot=k panic=1 nomodules root=/dev/vda3" --cpus boot=4 --memory size=1024M --net "tap=,mac=,ip=,mask=" --rng --log-file log.log -vvv

