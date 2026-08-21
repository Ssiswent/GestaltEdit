import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Force-quit Camera first. Choose ONE beta-5-style bundle-aware preheat below. When invoked=true appears, immediately go Home and directly long-press Camera Control. Do not manually open Camera first. Test the two bundle targets separately."
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false
    @State private var backgroundTask: UIBackgroundTaskIdentifier = .invalid

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Beta 5 Bundle-Aware Preheat A/B", systemImage: "bolt.horizontal.circle")
                            .font(.headline)

                        Text("24A5390f → 24A5408d adds VisionKitCore use of preheatFor:environmentBundleIdentifier:. This experiment calls the same API already present on your beta 4, guarded by exact ABI checks and two independently observed requestType/viEntryType values of 0. It does not patch Camera and cannot backport beta 5's separate GenerativeModels transient-cache fix.")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        Text("Test A first. If Camera still falls back to Photo, force-quit Camera again, return here, then test B.")
                            .font(.caption)
                            .fontWeight(.semibold)

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
                        Button { runCameraPreheat() } label: {
                            Label(isWorking ? "Running…" : "A: com.apple.camera", systemImage: "camera.fill")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isWorking)

                        Button { runTamalePreheat() } label: {
                            Label(isWorking ? "Running…" : "B: VisualIntelligenceCamera", systemImage: "viewfinder")
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
            .navigationTitle("VI Beta 5 Preheat")
            .navigationBarTitleDisplayMode(.inline)
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-iOS27-VI-Beta5-BundleAware-Preheat-AB"
            ) { _ in }
        }
    }

    private func runCameraPreheat() {
        runProbe { VIPreheat5408EmulationGenerateCameraReport() }
    }

    private func runTamalePreheat() {
        runProbe { VIPreheat5408EmulationGenerateVisualIntelligenceCameraReport() }
    }

    private func runProbe(_ operation: () -> String) {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        report = operation()
        if report.contains("invoked=true") {
            keepAliveForDirectCameraControlTest()
        }
        isWorking = false
    }

    private func keepAliveForDirectCameraControlTest() {
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
        }

        var task: UIBackgroundTaskIdentifier = .invalid
        task = UIApplication.shared.beginBackgroundTask(withName: "VI Beta5 Preheat A/B") {
            if task != .invalid {
                UIApplication.shared.endBackgroundTask(task)
                task = .invalid
            }
        }
        backgroundTask = task

        DispatchQueue.main.asyncAfter(deadline: .now() + 8) {
            if backgroundTask != .invalid {
                UIApplication.shared.endBackgroundTask(backgroundTask)
                backgroundTask = .invalid
            }
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
