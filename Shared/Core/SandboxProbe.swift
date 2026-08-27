import Foundation
import OSLog

/// Measures exactly what each of the three processes is allowed to do.
///
/// This exists because the milestone-1 run produced a result that no documentation states:
/// `NEFilterDataProvider` got `EPERM` opening a file in the App Group container that
/// `NEFilterControlProvider` opened fine, in the same second, with identical entitlements. Whether
/// that boundary is "no writes" or "no access at all" decides the entire milestone-2 architecture,
/// so it is measured rather than guessed.
///
/// Runs once per process at start-up. Cheap, and it cleans up after itself.
public enum SandboxProbe {

    public struct Result: Sendable {
        public let name: String
        public let ok: Bool
        public let detail: String
    }

    @discardableResult
    public static func run() -> [Result] {
        var results: [Result] = []
        func note(_ name: String, _ ok: Bool, _ detail: String = "") {
            results.append(Result(name: name, ok: ok, detail: detail))
        }

        guard let container = SharedContainer.containerURL else {
            note("containerURL", false, "nil")
            emit(results)
            return results
        }
        note("containerURL", true, container.lastPathComponent)

        // Can we even see the directory?
        var info = stat()
        errno = 0
        let statOK = stat(container.path, &info) == 0
        note("stat(container)", statOK, statOK ? "" : errnoText())

        do {
            let entries = try FileManager.default.contentsOfDirectory(atPath: container.path)
            note("listContainer", true, "\(entries.count) entries")
        } catch {
            note("listContainer", false, "\(error)")
        }

        // Create + write + read a fresh file.
        let probe = container.appendingPathComponent("sandbox-probe.tmp")
        errno = 0
        let createFD = open(probe.path, O_RDWR | O_CREAT | O_TRUNC, 0o644)
        note("open(O_CREAT|O_RDWR)", createFD >= 0, createFD >= 0 ? "" : errnoText())
        if createFD >= 0 {
            var payload: UInt64 = 0x5341_4D41
            errno = 0
            let wroteOK = pwrite(createFD, &payload, 8, 0) == 8
            note("write", wroteOK, wroteOK ? "" : errnoText())
            var readback: UInt64 = 0
            errno = 0
            let readOK = pread(createFD, &readback, 8, 0) == 8 && readback == payload
            note("read", readOK, readOK ? "" : errnoText())
            close(createFD)
            try? FileManager.default.removeItem(at: probe)
        }

        // Read-only access to a file another process created. This is the one that matters: the
        // milestone-2 plan is app-compiles-policy → data-provider-reads-policy.
        for writer in SharedContainer.Writer.allCases {
            guard let url = SharedContainer.ringURL(for: writer) else { continue }
            guard FileManager.default.fileExists(atPath: url.path) else {
                note("openRO(\(writer.rawValue).ring)", false, "absent")
                continue
            }
            errno = 0
            let fd = open(url.path, O_RDONLY)
            note("openRO(\(writer.rawValue).ring)", fd >= 0, fd >= 0 ? "" : errnoText())
            if fd >= 0 {
                var byte: UInt8 = 0
                errno = 0
                let ok = pread(fd, &byte, 1, 0) == 1
                note("preadRO(\(writer.rawValue).ring)", ok, ok ? "" : errnoText())
                close(fd)
            }
        }

        if let configURL = SharedContainer.configurationURL {
            if FileManager.default.fileExists(atPath: configURL.path) {
                do {
                    let data = try Data(contentsOf: configURL)
                    note("readConfig", true, "\(data.count) bytes")
                } catch {
                    note("readConfig", false, "\((error as NSError).code)")
                }
            } else {
                note("readConfig", false, "absent")
            }
        }

        // Private container, for comparison — tells us whether the restriction is App-Group-specific
        // or a blanket filesystem denial.
        let privateProbe = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Caches/sandbox-probe.tmp")
        errno = 0
        let privateFD = open(privateProbe.path, O_RDWR | O_CREAT | O_TRUNC, 0o644)
        note("privateContainerWrite", privateFD >= 0, privateFD >= 0 ? "" : errnoText())
        if privateFD >= 0 {
            close(privateFD)
            try? FileManager.default.removeItem(at: privateProbe)
        }

        // getifaddrs visibility. The data provider reported `tunnels=none` while the control
        // provider, at the same moment, saw seven — so interface enumeration is restricted too.
        let interfaces = NetworkInterfaces.current()
        note("getifaddrs", !interfaces.isEmpty,
             "\(interfaces.count) addrs, \(interfaces.filter(\.isTunnel).count) on tunnels, "
             + "names=\(Set(interfaces.map(\.name)).sorted().joined(separator: "/"))")

        emit(results)
        return results
    }

    private static func emit(_ results: [Result]) {
        func status(_ name: String) -> String {
            guard let match = results.first(where: { $0.name == name }) else { return "?" }
            return match.ok ? "OK" : "FAIL"
        }
        Log.storage.log("""
            [\(Log.process, privacy: .public)] ▶ PROBE SUMMARY \
            container=\(status("containerURL"), privacy: .public) \
            create=\(status("open(O_CREAT|O_RDWR)"), privacy: .public) \
            write=\(status("write"), privacy: .public) \
            readRO=\(status("openRO(control.ring)"), privacy: .public) \
            private=\(status("privateContainerWrite"), privacy: .public) \
            ifaces=\(status("getifaddrs"), privacy: .public)
            """)
        for result in results {
            Log.storage.log("""
                [\(Log.process, privacy: .public)] probe \(result.name, privacy: .public)=\
                \(result.ok ? "OK" : "FAIL", privacy: .public) \(result.detail, privacy: .public)
                """)
        }
    }

    private static func errnoText() -> String {
        errno == 0 ? "" : "errno=\(errno) \(String(cString: strerror(errno)))"
    }
}
