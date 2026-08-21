import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Open Camera once, return here without force-quitting it, then tap Run Process Probe. For Tamale/Visual Intelligence, invoke it once, return here, and run again. This build performs read-only process/code-signing queries only."
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("VI Live Process Entitlements", systemImage: "signature")
                            .font(.headline)

                        Text("The previous file-based entitlement probe was blocked by ContainerManager for Camera/Tamale. This version avoids protected app-file reads and instead enumerates live/suspended processes, then asks the kernel for their code-signing status and entitlement blob via read-only csops queries. No task_for_pid or process-memory access is used.")
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
                        Label(isWorking ? "Running…" : "Run Process Probe", systemImage: "play.fill")
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
            .navigationTitle("VI Process Entitlements")
            .navigationBarTitleDisplayMode(.inline)
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-iOS27-VI-Live-Process-Entitlements"
            ) { _ in }
        }
    }

    private func runProbe() {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        report = VIProcessEntitlementGenerateReport()
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
