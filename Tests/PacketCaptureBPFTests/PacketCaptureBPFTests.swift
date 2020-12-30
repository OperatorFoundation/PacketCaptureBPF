import XCTest
@testable import PacketCaptureBPF

final class PacketCaptureBPFTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
    }

    static var allTests = [
        ("testExample", testExample),
    ]
    
    func testInitBPF() {
        guard let bpfDevice = CaptureDevice(interface: "en0") else
        {
            XCTFail()
            return
        }
        
        do {
            try bpfDevice.startCapture()
        } catch (let startError){
            print("error: \(startError)")
            XCTFail()
            return
        }
        
        
        for i in 0...100{
            print("Read # \(i)")
            guard let captureResult = bpfDevice.nextCaptureResult() else
            {
                XCTFail()
                return
            }
            
            let droppedPackets = captureResult.dropped
            print("dropped packets: \(droppedPackets)\n")
            if droppedPackets > 0
            {
                XCTFail()
                return
            }
            
            let packets = captureResult.packets

            print("packet count: \(packets.count)")
//            print("packets:")
//            var packetCount = 0
//            for packet in packets
//            {
//                packetCount += 1
//                print("Packet #: \(packetCount)")
//                print("timestamp: \(packet.timestamp)")
//                print("bytes in packet: \(packet.payload.count)")
//            }
            
            
        }
        
    }
    
    
    
}
