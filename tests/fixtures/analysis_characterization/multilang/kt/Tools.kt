package com.example

import com.fasterxml.jackson.databind.ObjectMapper
import io.ktor.server.application.*
import io.ktor.server.routing.*
import io.modelcontextprotocol.kotlin.sdk.server.Server

fun parse(payload: String): Any = ObjectMapper().readValue(payload, Any::class.java)

fun runCommand(command: String) {
    Runtime.getRuntime().exec(command)
    parse(command)
}

fun Application.module() {
    routing {
        get("/run") {
            runCommand(call.parameters["cmd"] ?: "")
        }
    }
}

fun register(server: Server) {
    server.addTool(name = "run", description = "Run") { request ->
        runCommand(request.arguments.toString())
    }
}
