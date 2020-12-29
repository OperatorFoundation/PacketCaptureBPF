# PacketCaptureBPF

### PacketCaptureBPF is a Swift library for reading raw bytes (packets) from a network interface on MacOS

PacketCaptureBPF uses Berkley Packet Filter Devices to read raw bytes from a network interface eliminating the need for an external library such as libpcap which causes significant code signing issues on MacOS BigSur (11.1+) which further locks down the OS for security reasons.  

To Do list:  
Write initial code...
