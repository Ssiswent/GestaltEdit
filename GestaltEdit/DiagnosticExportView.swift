import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Tap Run Preflight Xref. This build does not invoke Camera or any VI availability API. It maps the exact Siri-AI/Apple-Intelligence preflight strings added in 24A5390f back to ARM64 code references and function-start boundaries inside the currently loaded VisualIntelligenceCore image."
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Camera Siri-AI Preflight Xref", systemImage: "scope")
                            .font(.headline)

                        Text("Exact-build IPSW diffs show that 24A5390f added Camera-specific Apple Intelligence/Siri-AI preflight strings to VisualIntelligenceCore while the Camera executable itself barely changed. This probe therefore resolves those exact strings to ARM64 ADR/ADRP references and LC_FUNCTION_STARTS boundaries, and lists only related Objective-C/Swift metadata. It performs no private availability calls.")
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
                        Label(isWorking ? "Running…" : "Run Preflight Xref", systemImage: "play.fill")
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
            .navigationTitle("VI Preflight Xref")
            .navigationBarTitleDisplayMode(.inline)
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-iOS27-VI-Camera-SiriAI-Preflight-Xref"
            ) { _ in }
        }
    }

    private func runProbe() {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        report = VICameraSiriPreflightXrefGenerateReport()
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
