import XCTest
@testable import PacketCaptureBPF

final class PacketCaptureBPFTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(PacketCaptureBPF().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
