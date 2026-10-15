import Foundation

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var stats: AppStats?
    @Published private(set) var activation = "Not requested yet"
    @Published private(set) var coreError: String?

    private let core: CoreBridge?
    private let extensions = ExtensionManager()
    private var ticks = 0

    init() {
        var openError: String?
        var opened: CoreBridge?
        do {
            opened = try CoreBridge(databaseURL: Self.databaseURL())
        } catch {
            openError = String(describing: error)
        }
        core = opened
        coreError = openError
        extensions.onChange = { [weak self] text in
            self?.activation = text
        }
        Task { [weak self] in
            while !Task.isCancelled {
                self?.tick()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    func activate() {
        extensions.activate()
    }

    private func tick() {
        guard let core else { return }
        ticks += 1
        // Reconnect every five seconds while the extension is not reachable.
        if stats?.connected != true, ticks % 5 == 1 {
            core.startStreaming()
        }
        stats = core.stats()
    }

    /// ~/Library/Application Support/dev.susanb.porchlight/events.db, owner-only.
    static func databaseURL() throws -> URL {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let dir = base.appendingPathComponent("dev.susanb.porchlight", isDirectory: true)
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return dir.appendingPathComponent("events.db")
    }
}
