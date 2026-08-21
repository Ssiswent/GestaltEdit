import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "For the real VI entry path, do NOT open Camera first. For a clean cold-launch test, swipe Camera away from the app switcher, return here, tap Start 8s Test, then immediately long-press Camera Control to invoke Visual Intelligence directly."
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Direct Camera Control VI Cache Test", systemImage: "camera.aperture")
                            .font(.headline)

                        Text("Corrected for the actual user flow: Camera Visual Intelligence is invoked by long-pressing Camera Control directly. Native logs show Camera can compute AIAvailability before it registers the GMS Darwin observer during launch. This test therefore keeps GestaltEdit alive briefly in the background and repeats only the transient com.apple.gms.availability.notification for 8 seconds while Camera is launched by the hardware control. It does not write preferences, MobileGestalt, files, or availability values.")
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

                        Button { runDirectTest() } label: {
                            Label(isWorking ? "8s Window Active…" : "Start 8s Test", systemImage: "camera.fill")
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
            .navigationTitle("Direct VI Test")
            .navigationBarTitleDisplayMode(.inline)
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-iOS27-VI-DirectCameraControl-CacheRefresh"
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

    private func runDirectTest() {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        report = GMSCacheRefreshDiagnostic.directCameraControlTestStartingReport()

        GMSCacheRefreshDiagnostic.startDirectCameraControlRefreshWindow { completedReport in
            report = completedReport
            isWorking = false
        }
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
