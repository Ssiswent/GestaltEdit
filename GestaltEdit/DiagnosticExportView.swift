import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Force-quit Camera first. Then tap Emulate 24A5408d Preheat. After the report appears, immediately go Home and directly long-press Camera Control. Do not open Camera manually first."
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("24A5408d Bundle-Aware Preheat", systemImage: "bolt.horizontal.circle")
                            .font(.headline)

                        Text("Exact-build IPSW diffs show that 24A5390f introduced VI coordinator configuration with requestType + environmentBundleIdentifier, while 24A5408d immediately added VisionKitCore calls to preheatFor:environmentBundleIdentifier:. This experiment uses only the requestType returned by a fresh config getter and preheats with com.apple.camera. It is transient and does not modify system configuration.")
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
                        Label(isWorking ? "Preheating…" : "Emulate 24A5408d Preheat", systemImage: "bolt.fill")
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
            .navigationTitle("VI 5408d Preheat")
            .navigationBarTitleDisplayMode(.inline)
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-iOS27-VI-24A5408d-BundleAware-Preheat"
            ) { _ in }
        }
    }

    private func runProbe() {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        report = VIPreheat5408EmulationGenerateReport()
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
