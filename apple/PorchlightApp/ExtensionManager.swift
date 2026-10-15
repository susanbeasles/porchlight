import Foundation
import SystemExtensions

/// Asks macOS to install or update the Endpoint Security extension (SPEC §6).
final class ExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    static let identifier = "dev.susanb.porchlight.extension"

    /// Called on the main queue with a plain-language status line.
    var onChange: ((String) -> Void)?

    func activate() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.identifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        onChange?("Asked macOS to install the extension")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        onChange?("Waiting for you to allow it in System Settings")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        switch result {
        case .completed:
            onChange?("Installed")
        case .willCompleteAfterReboot:
            onChange?("Installed; restart the Mac to finish")
        @unknown default:
            onChange?("Finished")
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        onChange?("Could not install: \(error.localizedDescription)")
    }
}
