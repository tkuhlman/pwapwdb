# I need to make this into a set of github actions or build configs for the app or something
wasm-pack build --target web --out-name wasm --out-dir ./static

# `python3 -m http.server` in the root is the easiest way (if already installed) to run it for debugging
# an alternative is `cargo install miniserver` folllowed by `miniserve ./static --index index.html`
# for either then browse to http://127.0.0.1:8000

# For install to a github pages, I should build it the copy over all the files in the service-worker.js cache list