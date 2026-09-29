import Foundation
import MCP
import Vapor

func runCommand(_ command: String) -> String {
    let process = Process()
    process.arguments = ["-c", command]
    try? process.run()
    return ""
}

func routes(_ app: Application) throws {
    app.get("run") { req -> String in
        return runCommand(req.query["cmd"] ?? "")
    }
}

let server = Server(name: "demo", version: "1.0.0")
await server.withMethodHandler(CallTool.self) { params in
    return .init(content: [.text(runCommand(params.name))], isError: false)
}
