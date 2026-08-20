import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct DiagnosticExportView: View {
    @State private var report = "Reading MobileGestalt…"
    @State private var isExporting = false
    @State private var copied = false
    @State private var showApplyConfirmation = false
    @State private var showRevertConfirmation = false
    @State private var operationMessage: String?
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        experimentalSection

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
            .navigationTitle("VI Diagnostic")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: report) {
                        Image(systemName: "square.and.arrow.up")
                    }
                }
            }
            .task {
                refresh()
            }
            .fileExporter(
                isPresented: $isExporting,
                document: DiagnosticTextDocument(text: report),
                contentType: .plainText,
                defaultFilename: "GestaltEdit-MobileGestalt-Diagnostic"
            ) { _ in }
            .confirmationDialog(
                "Apply experimental China SKU override?",
                isPresented: $showApplyConfirmation,
                titleVisibility: .visible
            ) {
                Button("Apply Override", role: .destructive) {
                    applyOverride()
                }
                Button("Cancel", role: .cancel) { }
            } message: {
                Text("This writes only two Boolean CacheExtra values: green-tea=false and not-green-tea=true. A MobileGestalt backup is created first. There is still a non-zero risk of system instability or failure to boot. The app will NOT reboot or respring automatically.")
            }
            .confirmationDialog(
                "Remove China SKU override keys?",
                isPresented: $showRevertConfirmation,
                titleVisibility: .visible
            ) {
                Button("Remove Override Keys", role: .destructive) {
                    revertOverride()
                }
                Button("Cancel", role: .cancel) { }
            } message: {
                Text("This removes only the two experimental CacheExtra keys added by this build. A backup of the current MobileGestalt file is created first.")
            }
            .alert(
                "China SKU Experiment",
                isPresented: Binding(
                    get: { operationMessage != nil },
                    set: { if !$0 { operationMessage = nil } }
                )
            ) {
                Button("OK") { operationMessage = nil }
            } message: {
                Text(operationMessage ?? "")
            }
        }
    }

    private var experimentalSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Experimental China SKU Override", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)

            Text("For Camera Visual Intelligence diagnosis only. This attempts to override the Chinese-market MobileGestalt identity without changing ProductType, HardwareModel, CPUModel, RegionCode, RegionInfo, or CacheData.")
                .font(.subheadline)

            Text(ChinaSKUOverride.cacheExtraStateDescription())
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                Button {
                    showApplyConfirmation = true
                } label: {
                    Label("Apply Override", systemImage: "wrench.and.screwdriver")
                }
                .buttonStyle(.borderedProminent)
                .tint(.orange)
                .disabled(isWorking)

                Button {
                    showRevertConfirmation = true
                } label: {
                    Label("Revert", systemImage: "arrow.uturn.backward")
                }
                .buttonStyle(.bordered)
                .disabled(isWorking)
            }

            Text("Safety behavior: automatic backup before every write, refuses to overwrite pre-existing values, verifies the written plist, and does not automatically reboot/respring. After a successful write, restart the iPhone yourself and then tap Refresh to check whether MGCopyAnswer changes.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func refresh() {
        copied = false
        report = MobileGestaltReadOnlyDiagnostic.generateReport()
    }

    private func applyOverride() {
        guard !isWorking else { return }
        isWorking = true
        defer { isWorking = false }

        do {
            let result = try ChinaSKUOverride.apply()
            refresh()
            operationMessage = result.message
        } catch {
            refresh()
            operationMessage = "No reboot was performed. Operation failed: \(error.localizedDescription)"
        }
    }

    private func revertOverride() {
        guard !isWorking else { return }
        isWorking = true
        defer { isWorking = false }

        do {
            let result = try ChinaSKUOverride.revert()
            refresh()
            operationMessage = result.message
        } catch {
            refresh()
            operationMessage = "Operation failed: \(error.localizedDescription)"
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
