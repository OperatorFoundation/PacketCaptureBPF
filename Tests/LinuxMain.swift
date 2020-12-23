import XCTest

import PacketCaptureBPFTests

var tests = [XCTestCaseEntry]()
tests += PacketCaptureBPFTests.allTests()
XCTMain(tests)
