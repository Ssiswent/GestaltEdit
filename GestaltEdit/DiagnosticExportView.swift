import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Running valid-request VI + China-policy diagnostic…"
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("VI Valid Request + China Policy", systemImage: "doc.text.magnifyingglass")
                            .font(.headline)

                        Text("Read-only diagnostic. It uses only requestType 0, which the previous crash-safe probe proved is the default/valid VIC request type on this exact build. It compares bundle-aware rich-analysis availability and inspects GreymatterAvailability runtime metadata, including the newly discovered China-policy field names. No arbitrary enum values, setters, preheat, swizzling, MobileGestalt writes, or system preference writes are used.")
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
            .navigationTitle("VI Policy Probe")
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
                defaultFilename: "GestaltEdit-iOS27-VI-ValidRequest-ChinaPolicy"
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
