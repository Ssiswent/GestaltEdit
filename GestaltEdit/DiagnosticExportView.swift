import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Tap Run LS Proxy Probe. This build does not enumerate processes or read protected app executables; it asks LaunchServices for the registered application proxy for Camera/Tamale/ScreenshotServicesService and, only if the current runtime exposes a read-only entitlements object getter with the expected ABI, reads it."
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("VI LaunchServices Proxy", systemImage: "app.badge.checkmark")
                            .font(.headline)

                        Text("proc_listallpids is denied to the third-party sandbox on this device, and direct Camera.app reads are blocked by ContainerManager. This version instead resolves installed-system application records by bundle identifier through LSApplicationProxy. No process enumeration or filesystem escape is used.")
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
                        Label(isWorking ? "Running…" : "Run LS Proxy Probe", systemImage: "play.fill")
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
            .navigationTitle("VI LS Proxy")
            .navigationBarTitleDisplayMode(.inline)
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-iOS27-VI-LaunchServices-AppProxy"
            ) { _ in }
        }
    }

    private func runProbe() {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        report = VILSApplicationProxyGenerateReport()
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
