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
import SwiftQueue

//magic values, to retrieve C MACRO values see PacketCaptureBPF/getMagicValues/main.c
let BPF_MINBUFSIZE: UInt = 32
let BPF_MAXBUFSIZE: UInt = 524288
let BPF_MAXINSNS: UInt = 512
let BPF_ALIGNMENT: UInt = 4
//#define BPF_WORDALIGN(x) (((x)+(BPF_ALIGNMENT-1))&~(BPF_ALIGNMENT-1))
// BPF_WORDALIGN(81) = 84
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
    var fd_bpf: Int32 = 0
    var buffer_size: UInt = 8192  // 8192 seems to work ok, but size may need to be adjusted, libpcap has a routine to automatically size the buffer apropriately
    var buffer = [UInt8](repeating:0, count: Int(8192))
    let packets = Queue<(Date, Data)>()
    
    var if_req = ifreq()
    var capturing: Bool = false
    
    public init?(interface: String)
    {
        
        // accept an interface name
        // does the interface exist and is it up
        
        guard let interfaceNameArray = interface.data.array(of: Int8.self) else
        {
            return nil
        }
        
        let ifr_name: [Int8] = paddedArray(source: interfaceNameArray, targetSize: 16, padValue: 0)
        
        if_req.ifr_name = (ifr_name[0], ifr_name[1], ifr_name[2], ifr_name[3], ifr_name[4], ifr_name[5], ifr_name[6], ifr_name[7], ifr_name[8], ifr_name[9], ifr_name[10], ifr_name[11], ifr_name[12], ifr_name[13], ifr_name[14], ifr_name[15])
        //print("interface name defined")
        
        // find next available/free bpf device
        // open bpf device
        var fd: Int32 = -1
        for i in 0...99 {
            let dev: String = "/dev/bpf" + i.string
            fd = open(dev, O_RDWR)
            if fd != -1 {
                self.fd_bpf = fd
                //print("Our bpf device is: \(dev)")
                //print("bpf fd is: \(fd_bpf)")
                break
            }
        }
        
        if fd == -1
        {
            return nil
        }
        
        // return/struct the bpf device fd so that it can be used in nextPacket()
        //print("reached end of init")
        //return
        
    }
    
    public enum BPFerror: Error
    {
        case couldNotSetBufferSize
        case couldNotBindInterfaceToBPF
        case couldNotEnablePromisciousMode
        case couldNotCloseBPFFileHandle
    }
    
    public func startCapture() throws {
        self.capturing = true
        // set buffer size
        guard Int(ioctl(self.fd_bpf, BIOCSBLEN, &self.buffer_size)) == 0 else
        {
            throw BPFerror.couldNotSetBufferSize
        }
        //print("buffer size set")
        
        // bind interface to the bpf device
        guard Int(ioctl(self.fd_bpf, BIOCSETIF, &if_req)) == 0 else
        {
            throw BPFerror.couldNotBindInterfaceToBPF
        }
        //print("bound interface to bpf")
        
        // enable promiscious mode
        // ioctl(fd, BIOCPROMISC, NULL)
        guard Int( ioctl(self.fd_bpf, BIOCPROMISC, 0 )) == 0 else
        {
            throw BPFerror.couldNotEnablePromisciousMode
        }
        //print("enabled promiscious mode")
        
    }
    
    
    public func stopCapture() throws {
        self.capturing = false
        guard Int(close(self.fd_bpf)) == 0 else
        {
            throw BPFerror.couldNotCloseBPFFileHandle
        }
    }
    
    
    public func nextCaptureResult() -> CaptureResult?
    {
        var packets: [TimestampedPacket] = [TimestampedPacket]()
        
        //has the buffer overflowed?
        struct bpf_stat_struct {
            var bs_recv: UInt32   /* number of packets received */
            var bs_drop: UInt32  /* number of packets dropped */
        };
        
        var bpf_stat = bpf_stat_struct(bs_recv: 0, bs_drop: 0)
        
        _ = ioctl(self.fd_bpf, BIOCGSTATS, &bpf_stat)
        //print("bpf_stat: \(bpf_stat)")
        
        let droppedPackets = Int(bpf_stat.bs_drop)
        
        
        // read from bpf device into buffer
        let len = read(self.fd_bpf, &self.buffer, Int(self.buffer_size) )
        
        guard len != -1 else
        {
            return nil
        }
        
        // keep only the bytes that were read, throw out the extra bytes in the buffer
        let lenAligned = (((UInt32(len)) + (UInt32(BPF_ALIGNMENT) - 1)) & (~(UInt32(BPF_ALIGNMENT) - 1)))
        let buffData = Data(self.buffer).subdata(in: 0..<Int(lenAligned))
        
        if len > 0
        {
            //print("length read: \(len)")
            
            //print("bpf read bytes:")
            //printDataBytes(bytes: buffData, hexDumpFormat: false, seperator: " ", decimal: false)
            
            
            //parse buffer into packets by looking at bpf header
            var bits = Bits(data: buffData)
            //print("bits.count: \(bits.count/8)")
            
            while bits.count > 0
            {
                //get the seconds
                DatableConfig.endianess = .little
                guard let tv_sec_bits = bits.unpack(bytes: 4) else
                {
                    //print("ERROR at sec unpack")
                    return nil
                }
                guard let tv_sec = tv_sec_bits.uint32 else
                {
                    //print("ERROR at sec uint32")
                    return nil
                }
                //print("time, tv_sec: \(tv_sec)")
                
                //get the microseconds
                guard let tv_usec_bits = bits.unpack(bytes: 4) else
                {
                    //print("ERROR at usec unpack")
                    return nil
                }
                guard let tv_usec = tv_usec_bits.uint32 else
                {
                    //print("ERROR at usec uint32")
                    return nil
                }
                //print("time, tv_usec: \(tv_usec)")
                
                let seconds = UInt64(tv_sec) //convert seconds to microsecs
                let microSecs = UInt64(tv_usec)
                let totalMicroSecs = seconds * UInt64(1e6) + microSecs
                let totalSeconds = totalMicroSecs / 1000000
                let date = Date(timeIntervalSince1970: TimeInterval(totalSeconds))
                
                // get the capture portion length, 4 bytes uint32
                guard let bh_caplen_bits = bits.unpack(bytes: 4) else
                {
                    //print("ERROR at cap len unpaack")
                    return nil
                }
                guard let bh_caplen = bh_caplen_bits.uint32 else
                {
                    //print("ERROR at cap len uint32")
                    return nil
                }
                //print("bh_caplen: \(bh_caplen)")
                
                
                // get the original packet length, 4 bytes uint32
                guard let bh_datalen_bits = bits.unpack(bytes: 4) else
                {
                    //print("ERROR at data len unpack")
                    return nil
                }
                guard let bh_datalen = bh_datalen_bits.uint32 else
                {
                    //print("ERROR at data len uint32")
                    return nil
                }
                //print("bh_datalen: \(bh_datalen)")
                
                
                // get the bpf header length, 2 bytes uint16 or unsigned short
                guard let bh_hdrlen_bits = bits.unpack(bytes: 2) else
                {
                    //print("ERROR at header len unpack")
                    return nil
                }
                guard let bh_hdrlen = bh_hdrlen_bits.uint16 else
                {
                    //print("ERROR at header len uint16")
                    return nil
                }
                //print("bh_hdrlen: \(bh_hdrlen)")
                
                //bpf is byte aligned
                let bytesToRead = (((UInt32(bh_hdrlen) + bh_caplen) + (UInt32(BPF_ALIGNMENT) - 1)) & (~(UInt32(BPF_ALIGNMENT) - 1))) - UInt32(bh_hdrlen)
                //print("bytesToRead: \(bytesToRead)")
                
                //let padding = bytesToRead - bh_caplen
                //print("padding: \(padding)")
                
                guard let packet = bits.unpack(bytes: Int(bytesToRead)) else
                {
                    //print("ERROR at packet unpack")
                    return nil
                }
                
                //print("packet:")
                //_ = printDataBytes(bytes: packet, hexDumpFormat: true, seperator: "", decimal: false)
                //print("")
                //print("bits.count: \(bits.count/8)")
                //print("")
                
                let data = Data(packet.data[0..<bh_datalen])
                
                let timestampedPacket = TimestampedPacket(timestamp: date, payload: data)
                packets.append(timestampedPacket)
                
            } //end of while bits.count > 0
        } //end of if len > 0
        
        return CaptureResult(packets:packets, dropped:droppedPackets)
    }
}




func paddedArray(source: [Int8], targetSize: Int, padValue: Int8) -> [Int8]
{
    var result: [Int8] = []
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


func printDataBytes(bytes: Data, hexDumpFormat: Bool, seperator: String, decimal: Bool, enablePrinting: Bool = true) -> String
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
