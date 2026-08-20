//
//  GestaltEditApp.swift
//  GestaltEdit
//

import SwiftUI

@main
struct GestaltEditApp: App {
    @StateObject private var viewModel = GestaltViewModel()

    init() {
        AutomationCommand.runIfNeeded()
        MobileGestaltReadOnlyDiagnostic.run()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
        }
    }
}
