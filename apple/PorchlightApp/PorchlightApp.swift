import SwiftUI

@main
struct PorchlightApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("Porchlight") {
            StatusView(model: model)
                .frame(minWidth: 560, minHeight: 460)
        }
    }
}
