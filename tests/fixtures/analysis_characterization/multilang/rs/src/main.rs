use rmcp::tool;
use serde_json::Value;
use std::process::Command;

fn parse(payload: &str) -> Value {
    serde_json::from_str(payload).unwrap_or(Value::Null)
}

#[tool(description = "Run a command")]
fn run(command: String) -> String {
    parse(&command);
    let output = Command::new("sh").arg("-c").arg(&command).output().unwrap();
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[actix_web::get("/run")]
async fn http_run(query: String) -> String {
    run(query)
}

fn main() {
    run("ls".to_string());
}
