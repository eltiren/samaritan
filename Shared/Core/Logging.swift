import Foundation
import OSLog

/// All Samaritan logging goes through one subsystem so the whole spike can be watched with:
///
///     log stream --predicate 'subsystem == "app.samaritan"' --level debug --style compact
///
/// Categories map to processes, which matters here: the point of the spike is partly to learn
/// *which* process the system actually invokes.
public enum Log {
    public static let subsystem = "app.samaritan"

    /// Which of the three processes is speaking.
    ///
    /// All three link the same `Shared` code, so a bare log line is ambiguous — the containing app
    /// opens both ring files and starts its own `PathObserver`, and therefore produces startup
    /// output almost identical to the extensions'. Every startup and path line carries this tag.
    public static let process: String = {
        switch Bundle.main.bundleIdentifier?.split(separator: ".").last {
        case "FilterData": "DATA"
        case "FilterControl": "CTRL"
        default: "APP"
        }
    }()

    public static let app = Logger(subsystem: subsystem, category: "App")
    public static let manager = Logger(subsystem: subsystem, category: "FilterManager")
    public static let data = Logger(subsystem: subsystem, category: "DataProvider")
    public static let control = Logger(subsystem: subsystem, category: "ControlProvider")
    public static let flows = Logger(subsystem: subsystem, category: "Flows")
    public static let storage = Logger(subsystem: subsystem, category: "Storage")
    public static let path = Logger(subsystem: subsystem, category: "Path")
    public static let policy = Logger(subsystem: subsystem, category: "Flows")   // shares the Flows category, which is the one idevicesyslog reliably delivers
}
