# PacketCaptureBPF

### PacketCaptureBPF is a high-level Swift interface to capture network traffic on MacOS using the Berkeley Packet Filter interface  

PacketCaptureBPF uses Berkeley Packet Filter Devices to read raw bytes from a network interface eliminating the need for an external library such as libpcap which causes significant code signing issues on MacOS BigSur (11.1+) because it further locks down the OS for security reasons.  

To Do list:  
Write initial code...
