//
//  CaptureDevice.swift
//  PacketCaptureBPF
//
//  Created by Jeremy Zunker on 12/28/20.
//

import Foundation
import PacketStream
import Datable
import Bits

//magic values, to retrieve C MACRO values see PacketCaptureBPF/getMagicValues/main.c
let BIOCGBLEN: UInt = 1074020966
let BIOCSBLEN: UInt = 3221504614
let BIOCGDLT: UInt = 1074020970
let BIOCGDLTLIST: UInt = 3222028921
let BIOCSDLT: UInt = 2147762808
let BIOCPROMISC: UInt = 536887913
let BIOCFLUSH: UInt = 536887912
let BIOCSETIF: UInt = 2149597804
let BIOCSRTIMEOUT: UInt = 2148549229
let BIOCGRTIMEOUT: UInt = 1074807406
let BIOCGSTATS: UInt = 1074283119
let BIOCIMMEDIATE: UInt = 2147762800
let BIOCSETF: UInt = 2148549223
let BIOCSETFNR: UInt = 2148549246
let BIOCVERSION: UInt = 1074020977
let BIOCSHDRCMPLT: UInt = 2147762805
let BIOCSSEESENT: UInt = 2147762807
let BIOCGSEESENT: UInt = 1074020982
let BIOCGRSIG: UInt = 1074020978
let BIOCSRSIG: UInt = 2147762803
let SIGIO: UInt = 23
let FIONREAD: UInt = 1074030207
let SIOCGIFADDR: UInt = 3223349537





public class CaptureDevice: PacketStream
{
    // add function to close things and tidy up when finished
    
    var fd_bpf: Int32 = 0
    var buffer_size: UInt = 4096  // size may need to be adjusted, libpcap has a routine to automatically size the buffer apropriately
    var buffer = [UInt8](repeating:0, count: Int(4096))
    //var buffer = Data(count: 4096)
    
    public init?(interface: String)
    {
        
        // accept an interface name
        // does the interface exist and is it up
        var if_req = ifreq()
        
        guard let interfaceNameArray = interface.data.array(of: Int8.self) else
        {
            return nil
        }
        
        let ifr_name: [Int8] = paddedArray(source: interfaceNameArray, targetSize: 16, padValue: 0)
        
        if_req.ifr_name = (ifr_name[0], ifr_name[1], ifr_name[2], ifr_name[3], ifr_name[4], ifr_name[5], ifr_name[6], ifr_name[7], ifr_name[8], ifr_name[9], ifr_name[10], ifr_name[11], ifr_name[12], ifr_name[13], ifr_name[14], ifr_name[15])
        print("interface name defined")
        
        // find next available/free bpf device
        // open bpf device
        var fd: Int32 = -1
        for i in 0...99 {
            let dev: String = "/dev/bpf" + i.string
            fd = open(dev, O_RDWR)
            if fd != -1 {
                self.fd_bpf = fd
                print("Our bpf device is: \(dev)")
                print("bpf fd is: \(fd_bpf)")
                break
            }
        }
        
        if fd == -1
        {
            return nil
        }
        
        // set buffer size
        guard Int(ioctl(self.fd_bpf, BIOCSBLEN, &self.buffer_size)) == 0 else
        {
            return nil
        }
        print("buffer size set")
        
        
        // bind interface to the bpf device
        guard Int(ioctl(self.fd_bpf, BIOCSETIF, &if_req)) == 0 else
        {
            return nil
        }
        print("bound interface to bpf")
        
        // enable promiscious mode
        // ioctl(fd, BIOCPROMISC, NULL)
        guard Int( ioctl(self.fd_bpf, BIOCPROMISC, 0 )) == 0 else
        {
            return nil
        }
        print("enabled promiscious mode")
        
        // return/struct the bpf device fd so that it can be used in nextPacket()
        print("reached end of init")
        return
        
    }
    
    public func nextPacket() -> (Date, Data)
    {
        
        // use the timestamp from bpf header for Date
        
        // return Date & Data
        // detect dropped packets
        /*
         BIOCGSTATS     (struct bpf_stat) Returns the following structure of packet statistics:
         
         struct bpf_stat {
         u_int bs_recv;    /* number of packets received */
         u_int bs_drop;    /* number of packets dropped */
         };
         
         The fields are:
         
         bs_recv the number of packets received by the descriptor since opened or reset (including any buffered since the last read call); and
         
         bs_drop the number of packets which were accepted by the filter but dropped by the kernel because of buffer overflows (i.e., the application's reads aren't keeping up with the packet traffic).
         */
        
        
        // read from bpf device into buffer
        let len = read(self.fd_bpf, &self.buffer, Int(self.buffer_size) )
        
        let buffData = Data(self.buffer)
        
        
        
        if len > 0
        {
            print("length read: \(len)")
            
            print("bpf read bytes:")
            printDataBytes(bytes: buffData, hexDumpFormat: false, seperator: " ", decimal: false)
            
            
            //parse buffer into packets by looking at bpf header
            var bits = Bits(data: buffData)
            
            while bits.count > 0
            {
                //get the seconds
                DatableConfig.endianess = .little
                guard let tv_sec_bits = bits.unpack(bytes: 4) else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                
                guard let tv_sec = tv_sec_bits.uint32 else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                print("time, tv_sec: \(tv_sec)")
                
                //get the microseconds
                guard let tv_usec_bits = bits.unpack(bytes: 4) else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                
                guard let tv_usec = tv_usec_bits.uint32 else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                print("time, tv_usec: \(tv_usec)")
                
                
                // get the capture portion length, 4 bytes uint32
                guard let bh_caplen_bits = bits.unpack(bytes: 4) else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                
                guard let bh_caplen = bh_caplen_bits.uint32 else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                print("bh_caplen: \(bh_caplen)")
                
                
                
                

                // get the original packet length, 4 bytes uint32
                guard let bh_datalen_bits = bits.unpack(bytes: 4) else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                
                guard let bh_datalen = bh_datalen_bits.uint32 else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                print("bh_datalen: \(bh_datalen)")
                
                
                
                
                
                
                // get the bpf header length, 2 bytes uint16 or unsigned short
                guard let bh_hdrlen_bits = bits.unpack(bytes: 2) else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                
                guard let bh_hdrlen = bh_hdrlen_bits.uint16 else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                print("bh_hdrlen: \(bh_hdrlen)")
                
                
                
                
                
                // get the data portion of the packet using the capture portion length
                guard let packet = bits.unpack(bytes: Int(bh_caplen)) else
                {
                    print("ERROR")
                    return (Date(), Data())
                }
                
                print("packet:")
                _ = printDataBytes(bytes: packet, hexDumpFormat: true, seperator: "", decimal: false)
                print("")
            
            }
            
            
            
            
            
            
            
            
            
            
            
            
            
            
        }
        
        //info->bpf_hdr = (struct bpf_hdr*)((long)sniffer->buffer + (long)sniffer->read_bytes_consumed);
        //info->data = sniffer->buffer + (long)sniffer->read_bytes_consumed + info->bpf_hdr->bh_hdrlen;
        
        /*
         #if defined(__LP64__)
         #include <sys/_types/_timeval32.h>
         
         #define BPF_TIMEVAL timeval32
         #else
         #define BPF_TIMEVAL timeval
         #endif /* __LP64__ */
         
         struct bpf_hdr {
         struct BPF_TIMEVAL bh_tstamp;   /* time stamp */
         bpf_u_int32     bh_caplen;      /* length of captured portion */
         bpf_u_int32     bh_datalen;     /* original length of packet */
         u_short         bh_hdrlen;      /* length of bpf header (this struct
         *  plus alignment padding) */
         };
         
         timestamp-secs, 32 bits, 4 bytes, 1-4
         timestamp-usecs, 32 bits, 4 bytes, 5-8
         capturePortionLength, 32 bits, 4 bytes, 9-12
         originalPacketLength, 32 bits, 4 bytes, 13-16
         headerLength 16bits, 2 bytes, 17-18
         
         struct timeval {
         long tv_sec;                /* seconds */
         long tv_usec;               /* microseconds */
         };
         
         _STRUCT_TIMEVAL32
         {
         __int32_t               tv_sec;         /* seconds */
         __int32_t               tv_usec;        /* and microseconds */
         };
         */
        
        
        
        
        return (Date(), Data())
    }
}




func paddedArray(source: [Int8], targetSize: Int, padValue: Int8) -> [Int8]
{
    var result: [Int8] = []
    //        result.append(padValue)
    //        result.append(padValue)
    //        result.append(Int8(0))
    for item in source
    {
        result.append(item)
    }
    
    for _ in result.count..<targetSize
    {
        result.append(padValue)
    }
    
    return result
}


public func printDataBytes(bytes: Data, hexDumpFormat: Bool, seperator: String, decimal: Bool, enablePrinting: Bool = true) -> String
{
    var returnString: String = ""
    if hexDumpFormat
    {
        var count = 0
        var newLine: Bool = true
        for byte in bytes
        {
            if newLine
            {
                if enablePrinting { print("・ ", terminator: "") }
                newLine = false
            }
            if enablePrinting { print(String(format: "%02x", byte), terminator: " ") }
            returnString += String(format: "%02x", byte)
            returnString += " "
            count += 1
            if count % 8 == 0
            {
                if enablePrinting { print(" ", terminator: "") }
                returnString += " "
            }
            if count % 16 == 0
            {
                if enablePrinting { print("") }
                returnString += "\n"
                newLine = true
            }
        }
    }
    else
    {
        var i = 0
        for byte in bytes
        {
            if decimal
            {
                if enablePrinting { print(String(format: "%u", byte), terminator: "") }
                returnString += String(format: "%u", byte)
            }
            else
            {
                if enablePrinting { print(String(format: "%02x", byte), terminator: "") }
                returnString += String(format: "%02x", byte)
            }
            i += 1
            if i < bytes.count
            {
                if enablePrinting { print(seperator, terminator: "") }
                returnString += seperator
            }
        }
    }
    if enablePrinting { print("") }
    return returnString
}
