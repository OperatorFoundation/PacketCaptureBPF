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
        let bpfDevice = CaptureDevice(interface: "en0")
        
        bpfDevice?.nextPacket()
        bpfDevice?.nextPacket()
        bpfDevice?.nextPacket()
        bpfDevice?.nextPacket()
        
    }
    
    
    
}
