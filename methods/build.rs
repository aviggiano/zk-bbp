use std::collections::HashMap;

fn main() {
    let mut methods = HashMap::new();
    methods.insert("guest", "guest");
    risc0_build::embed_methods_with_options(methods);
}