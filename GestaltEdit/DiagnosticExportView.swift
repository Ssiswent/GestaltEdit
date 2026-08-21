import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Use Snapshot for a read-only baseline. For the cache experiment, leave Camera alive in the app switcher, return here, tap Broadcast Refresh, then immediately return to Camera and test Visual Intelligence."
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("VI GMS / VK Cache Refresh", systemImage: "arrow.clockwise.circle")
                            .font(.headline)

                        Text("Targeted cache experiment based on native Camera logs: Camera reports com.apple.Settings.AppleIntelligence unavailable and then says it is returning a cached availability state, while other processes on the same device report the same use case as available. Snapshot is read-only. Broadcast Refresh only posts the transient Darwin notification already observed by GenerativeModels and VKCGMAvailability; it does not write preferences, MobileGestalt, files, or availability values.")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        Divider()

                        Text(report)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(16)
                }

                Divider()

                VStack(spacing: 10) {
                    HStack(spacing: 12) {
                        Button { runSnapshot() } label: {
                            Label("Snapshot", systemImage: "doc.text.magnifyingglass")
                        }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)

                        Button { runBroadcast() } label: {
                            Label(isWorking ? "Running…" : "Broadcast Refresh", systemImage: "arrow.clockwise")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isWorking)
                    }

                    HStack(spacing: 12) {
                        Button {
                            UIPasteboard.general.string = report
                            copied = true
                        } label: {
                            Label(copied ? "Copied" : "Copy", systemImage: "doc.on.doc")
                        }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)

                        Spacer()

                        Button { isExporting = true } label: {
                            Label("Export TXT", systemImage: "square.and.arrow.up")
                        }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)
                    }
                }
                .padding(16)
            }
            .navigationTitle("VI Cache Refresh")
            .navigationBarTitleDisplayMode(.inline)
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-iOS27-VI-GMS-VK-CacheRefresh"
            ) { _ in }
        }
    }

    private func runSnapshot() {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        report = GMSCacheRefreshDiagnostic.snapshotReport()
        isWorking = false
    }

    private func runBroadcast() {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        report = GMSCacheRefreshDiagnostic.broadcastAndMeasureReport()
        isWorking = false
    }
}

private struct DiagnosticTextDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText] }
    var text: String

    init(text: String) {
        self.text = text
    }

    init(configuration: ReadConfiguration) throws {
        if let data = configuration.file.regularFileContents,
           let text = String(data: data, encoding: .utf8) {
            self.text = text
        } else {
            self.text = ""
        }
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}
