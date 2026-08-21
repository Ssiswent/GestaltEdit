import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Tap Run Caller/Entitlement Probe. This build performs read-only inspection of the signed system binaries for Camera, visualintelligenced, Tamale, ScreenshotServicesService, SpringBoard, generativeexperiencesd, countryd and eligibilityd, then compares VI/GMS-relevant entitlements and service access."
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("VI Caller / Entitlement Differential", systemImage: "person.badge.key")
                            .font(.headline)

                        Text("The direct Camera-Control refresh-window test did not change Camera behavior, so this probe moves to process-specific initialization. It compares the embedded code-signing entitlements of Camera and the VI/GMS processes that succeed on the same device. Protected system paths are only read; no availability API, XPC service, preference, MobileGestalt value, file, or system state is modified.")
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

                HStack(spacing: 12) {
                    Button { runProbe() } label: {
                        Label(isWorking ? "Running…" : "Run Caller Probe", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isWorking)

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
                .padding(16)
            }
            .navigationTitle("VI Caller Probe")
            .navigationBarTitleDisplayMode(.inline)
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-iOS27-VI-Caller-Entitlement-Differential"
            ) { _ in }
        }
    }

    private func runProbe() {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        DispatchQueue.global(qos: .userInitiated).async {
            let value = ResolvedEntitlementProbe.generateReport()
            DispatchQueue.main.async {
                report = value
                isWorking = false
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
