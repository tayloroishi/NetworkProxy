#[path = "libs/server.rs"] pub mod server;

fn main() {
    let _server = server::Server {};
    _server.start();
}