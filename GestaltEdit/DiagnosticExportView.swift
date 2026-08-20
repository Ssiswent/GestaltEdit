import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Resolving current iOS 27 VI caller paths…"
    @State private var isExporting = false
    @State private var copied = false
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("VI Caller Path Probe", systemImage: "doc.text.magnifyingglass")
                            .font(.headline)

                        Text("Read-only diagnostic. Resolves current Camera / visualintelligenced / Tamale / ScreenshotServicesService paths and compares their embedded code-signing entitlements. Protected file reads use temporary bad_query leases only; no availability XPC call or system write is performed.")
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
                    Button {
                        refresh()
                    } label: {
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

                    Button {
                        isExporting = true
                    } label: {
                        Label("Export TXT", systemImage: "square.and.arrow.up")
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding(16)
            }
            .navigationTitle("VI Caller Probe")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: report) {
                        Image(systemName: "square.and.arrow.up")
                    }
                }
            }
            .task { refresh() }
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-iOS27-VI-Caller-Path-Diagnostic"
            ) { _ in }
        }
    }

    private func refresh() {
        guard !isWorking else { return }
        isWorking = true
        copied = false
        report = ResolvedEntitlementProbe.generateReport()
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