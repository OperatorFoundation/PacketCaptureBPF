import Foundation
import PacketStream

public class CaptureDevice: PacketStream
{
    public init?(interface: String)
    {
        return nil
    }

    public func nextPacket() -> (Date, Data)
    {
        return (Date(), Data())
    }
}
