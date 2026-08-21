import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Running crash-safe VI request-type inspection…"
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("VI Request-Type Crash-Safe Probe", systemImage: "doc.text.magnifyingglass")
                            .font(.headline)

                        Text("Read-only diagnostic. It does not call the enum-consuming isRichAnalysisAvailableForRequestType:bundleID: method. It reads ABI-verified VI getters and inspects Objective-C metadata plus loaded Mach-O reflection/cstring sections to identify the valid request/entry type without guessing raw enum values.")
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
                    Button { refresh() } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    .disabled(isWorking)

                    Button {
                        UIPasteboard.general.string = report
                        copied = true
                    } label: {
                        Label(copied ? "Copied" : "Copy", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.bordered)

                    Spacer()

                    Button { isExporting = true } label: {
                        Label("Export TXT", systemImage: "square.and.arrow.up")
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding(16)
            }
            .navigationTitle("VI Crash-Safe Probe")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: report) { Image(systemName: "square.and.arrow.up") }
                }
            }
            .task { refresh() }
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-iOS27-VI-RequestType-CrashSafe"
            ) { _ in }
        }
    }

    private func refresh() {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        report = CallerIdentityGenerateReport()
        isWorking = false
    }
}

private struct DiagnosticTextDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText] }
    var text: String
    init(text: String) { self.text = text }
    init(configuration: ReadConfiguration) throws {
        if let data = configuration.file.regularFileContents,
           let text = String(data: data, encoding: .utf8) { self.text = text }
        else { self.text = "" }
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}
