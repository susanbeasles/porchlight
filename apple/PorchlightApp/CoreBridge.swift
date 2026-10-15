import Foundation

// JSON shapes produced by pl_app_stats_json (crates/pl-ffi/src/core.rs). Snake case on the
// wire, converted by the decoder.

struct BridgeStats: Decodable {
    let rawEvents: UInt64
    let events: UInt64
    let decodeErrors: UInt64
    let truncated: UInt64
    let sequenceGaps: UInt64
    let sequenceGapMessages: UInt64
    let ringDrops: UInt64
    let disconnectedDrops: UInt64
    let batches: UInt64
}

struct ExtensionStatus: Decodable {
    let protocolVersion: Int64
    let state: String
    let streaming: Bool
    let ringCapacity: UInt32
    let producerOverlaps: UInt64
    let queuedWhileDisconnected: UInt64
    let bridge: BridgeStats
}

struct LiveStats: Decodable {
    let forks: UInt64
    let execs: UInt64
    let execPidversionChanged: UInt64
    let execPidversionSame: UInt64
    let exits: UInt64
    let exitsUntracked: UInt64
}

struct AppStats: Decodable {
    let connected: Bool
    let extensionStatus: ExtensionStatus?
    let eventsIngested: UInt64
    let highWater: UInt64
    let liveProcesses: Int
    let live: LiveStats
    let drops: [String: UInt64]
    let batches: UInt64
    let ingestErrors: UInt64
    let lastError: String?

    enum CodingKeys: String, CodingKey {
        case connected
        case extensionStatus = "extension"
        case eventsIngested, highWater, liveProcesses, live, drops, batches, ingestErrors, lastError
    }
}

enum CoreError: Error, CustomStringConvertible {
    case openFailed(String)

    var description: String {
        switch self {
        case .openFailed(let path): return "Could not open the event store at \(path)"
        }
    }
}

/// Owns the Rust core handle. All calls are cheap and thread-safe on the Rust side.
final class CoreBridge {
    private let handle: OpaquePointer
    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()

    init(databaseURL: URL) throws {
        guard let h = databaseURL.path.withCString({ pl_app_open($0) }) else {
            throw CoreError.openFailed(databaseURL.path)
        }
        handle = h
    }

    deinit {
        pl_app_close(handle)
    }

    /// 0 connected, -2 already connected, -3 failed (see stats.lastError).
    @discardableResult
    func startStreaming() -> Int32 {
        pl_app_connect(handle)
    }

    func stats() -> AppStats? {
        guard let cString = pl_app_stats_json(handle) else { return nil }
        defer { pl_string_free(cString) }
        let data = Data(bytes: cString, count: strlen(cString))
        return try? decoder.decode(AppStats.self, from: data)
    }
}
